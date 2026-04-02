#include <android/asset_manager.h>
#include <string>
#include <vector>
#include <filesystem>
#include "api.h"
#include "inlinehook.h"
#include <dlfcn.h>
#include <cstdint>
#include "Macro.h"

C {

// ============================================================
//  VirtualAssets
// ============================================================

/**
 * @defgroup VirtualAssets VirtualAssets API
 *
 * @brief Hooks the Android AAssetManager to layer a virtual filesystem
 *        transparently on top of the real APK asset tree.
 *
 * ### How the hook works
 * The NDK's AAssetManager_open (and its internal siblings) is intercepted via
 * HookManager. Every asset path opened by the game passes through the
 * interceptor, which checks the virtual registry before forwarding to the
 * real AAssetManager zip reader.
 *
 * ### Interception order (highest to lowest priority)
 *  1. **Blocked** – path returns failure immediately; the game sees the file
 *     as non-existent even though it is in the APK.
 *  2. **Virtual entry** – data registered by AddFile / AddTextFile / LoadDir /
 *     ReplaceFile is served to the caller instead of the APK data.
 *  3. **Fall-through** – the call is forwarded to the real AAssetManager and
 *     the APK data is returned unmodified.
 *
 * ### Thread safety
 * All functions are thread-safe after init_virtual_assets() returns. Internal
 * state is protected by a mutex; concurrent calls from the render thread,
 * audio thread, or mod worker threads are safe.
 *
 * @{
 */


/**
 * @brief Blocks an asset path so that the game cannot open it.
 *
 * Any AAssetManager_open call for @p path will return failure (null asset),
 * as if the file does not exist in the APK.
 *
 * Common uses:
 *  - Suppressing vanilla assets you are completely replacing.
 *  - Preventing a file from loading that crashes with your mod installed.
 *
 * Blocking has higher priority than virtual entries: even if a virtual entry
 * is registered for the same path, the file appears missing while blocked.
 * Lift the block with VirtualAssets_UnblockFile().
 *
 * @param path  Asset path relative to the APK assets root
 *              (e.g. "textures/terrain/grass.png"). Must not be nullptr.
 */
void VirtualAssets_BlockFile(const char* path);

/**
 * @brief Lifts a block previously applied by VirtualAssets_BlockFile().
 *
 * After this call the path resumes normal interception priority:
 * a virtual entry is served if one exists, otherwise the real APK data is returned.
 *
 * Has no effect if @p path is not currently blocked.
 *
 * @param path  Asset path to unblock; must match the string passed to BlockFile.
 */
void VirtualAssets_UnblockFile(const char* path);

/**
 * @brief Injects a binary blob as a virtual asset at @p path.
 *
 * The @p data buffer is copied into an internal store immediately; the caller
 * may free or reuse the buffer right after this call returns.
 *
 * If a virtual entry already exists at @p path it is replaced atomically.
 * If the path is currently blocked the entry is stored but invisible until
 * VirtualAssets_UnblockFile() is called.
 *
 * @param path  Virtual asset path to register (e.g. "shaders/glsl/terrain.vertex").
 * @param data  Raw bytes to inject. Must not be nullptr.
 * @param size  Number of bytes in @p data.
 */
void VirtualAssets_AddFile(const char* path, const void* data, size_t size);

/**
 * @brief Injects a UTF-8 text string as a virtual asset at @p path.
 *
 * Convenience wrapper around VirtualAssets_AddFile() for plain-text content
 * (JSON, XML, shader source, CSV, etc.). The content is copied internally; the
 * caller retains ownership of the @p content pointer. The null terminator is
 * NOT included in the stored byte count.
 *
 * @param path     Virtual asset path (e.g. "config/mod_settings.json").
 * @param content  Null-terminated UTF-8 string to store. Must not be nullptr.
 */
void VirtualAssets_AddTextFile(const char* path, const char* content);

/**
 * @brief Removes a virtual entry from the registry.
 *
 * After this call, opens for @p path fall through to the real AAssetManager
 * (or fail if the path is still blocked).
 *
 * Has no effect if @p path has no registered virtual entry.
 *
 * @param path  Virtual asset path to remove.
 */
void VirtualAssets_RemoveFile(const char* path);

/**
 * @brief Returns whether a virtual entry is registered for @p path.
 *
 * Returns true even if the path is currently blocked. Does NOT query whether
 * the file exists in the real APK.
 *
 * @param path  Virtual asset path to query.
 * @return true if a virtual entry exists for @p path.
 */
bool VirtualAssets_HasFile(const char* path);

/**
 * @brief Bulk-registers all files in an on-device directory as virtual assets.
 *
 * Walks @p storageDir on the real device filesystem and registers each file
 * as a virtual asset under @p virtualBaseDir, preserving relative subdirectory
 * structure.  Files are loaded **lazily** — the virtual entry stores the real
 * path and bytes are read only when the game actually opens the asset.  This
 * means you can edit files on storage and the changes are visible immediately
 * without calling LoadDir again.
 *
 * Example:
 * @code
 *   // Device:    /sdcard/MyMod/textures/grass.png
 *   // Served as: assets/textures/grass.png  in the virtual asset tree
 *   VirtualAssets_LoadDir("/sdcard/MyMod/textures", "textures", true);
 * @endcode
 *
 * @param storageDir      Absolute path to the source directory on the device
 *                        (e.g. "/sdcard/MyMod/assets"). Must exist and be readable.
 * @param virtualBaseDir  Prefix in the virtual asset tree where files are placed
 *                        (e.g. "textures/custom"). Pass "" to map directly under
 *                        the asset root.
 * @param recursive       true = traverse subdirectories and register their contents
 *                        recursively, preserving folder structure.
 *                        false = register only the immediate files in @p storageDir.
 * @return Number of files successfully registered; -1 if @p storageDir does not
 *         exist, is not a directory, or cannot be read.
 */
int VirtualAssets_LoadDir(const char* storageDir, const char* virtualBaseDir, bool recursive);

/**
 * @brief Points a virtual asset entry at an on-device file, replacing its contents.
 *
 * Creates or updates the virtual entry at @p virtualPath so that it is backed
 * by @p storagePath on the real filesystem. The file at @p storagePath is
 * read each time the asset is opened, so disk edits are visible immediately
 * without calling ReplaceFile again.
 *
 * Prefer this over VirtualAssets_AddFile() when the source data is a file on
 * device storage that may be updated while the game is running.
 *
 * @param virtualPath  Destination in the virtual asset tree
 *                     (e.g. "assets/textures/terrain/grass.png").
 * @param storagePath  Absolute path to the replacement file on the device
 *                     (e.g. "/sdcard/MyMod/grass.png"). Must be readable.
 * @return true if the virtual entry was created or updated successfully.
 *         false if @p storagePath cannot be accessed.
 */
bool VirtualAssets_ReplaceFile(const char* virtualPath, const char* storagePath);

/**
 * @brief Reads a virtual asset into a newly heap-allocated buffer.
 *
 * Only reads from the virtual registry — does NOT fall through to the real
 * AAssetManager. The caller is responsible for freeing the returned buffer
 * with free().
 *
 * @param path     Virtual asset path to read.
 * @param outSize  Out-param set to the size of the returned buffer in bytes.
 *                 Set to 0 on failure. Must not be nullptr.
 * @return Pointer to a malloc'd buffer containing the raw file bytes on success;
 *         nullptr if @p path is not in the virtual registry, is blocked, or
 *         memory allocation fails. Caller must free() the pointer.
 */
void* VirtualAssets_ReadFile(const char* path, size_t* outSize);

/**
 * @brief Overwrites the stored bytes of an existing virtual asset entry.
 *
 * Replaces the internally held data for @p path with @p data. The new bytes
 * are copied internally; the caller retains ownership of @p data.
 *
 * The entry at @p path must already exist. If it does not, call
 * VirtualAssets_AddFile() first to create it.
 *
 * @param path  Virtual asset path of the entry to update.
 * @param data  Pointer to the new raw bytes. Must not be nullptr.
 * @param size  Number of bytes in @p data.
 */
void VirtualAssets_EditFile(const char* path, const void* data, size_t size);

/** @} */ // end of VirtualAssets group

}

static const char* PARTICLES_MATERIAL = R"({
  "materials": {
    "version": "1.0.0",

    "particles_base": {
      "vertexShader": "shaders/color_uv.vertex",
      "vrGeometryShader": "shaders/color_uv.geometry",
      "fragmentShader": "shaders/color_texture.fragment",

      "vertexFields": [
        { "field": "Position" },
        { "field": "Color" },
        { "field": "UV0" }
      ],

      "+samplerStates": [
        {
          "samplerIndex": 0,
          "textureFilter": "Point"
        }
      ],

      "msaaSupport": "Both"
    },

    "particles_opaque:particles_base": {
      "+states": [ "DisableAlphaWrite" ]
    },

    "particles_alpha:particles_base": {
      "+defines": [ "ALPHA_TEST" ],
      "+states": [ "DisableAlphaWrite" ]
    },

    "particles_blend:particles_base": {
      "+states": [
        "Blending",
        "DisableDepthWrite"
      ]
    },

    "particles_effects:particles_alpha": {
      "+defines": [ "EFFECTS_OFFSET" ],
      "msaaSupport": "Both"
    },

    "particles_add:particles_blend": {
      "blendSrc": "SourceAlpha",
      "blendDst": "One"
    },

    "particles_random_test": {
      "vertexShader": "shaders/particle_random_test.vertex",
      "vrGeometryShader": "shaders/color_uv.geometry",
      "fragmentShader": "shaders/color_texture.fragment",

      "vertexFields": [
        { "field": "Position" },
        { "field": "Color" },
        { "field": "Normal" },
        { "field": "UV0" }
      ],

      "+samplerStates": [
        {
          "samplerIndex": 0,
          "textureFilter": "Point"
        }
      ],

      "+defines": [ "ALPHA_TEST" ],
      "+states": [ "DisableAlphaWrite" ],

      "msaaSupport": "Both"
    }
  }
})";

bool is_particles_material_file(const std::filesystem::path& c_path) {
    std::string path_str = c_path.string();

    if (!c_path.has_filename()) {
        return false;
    }

    std::string filename = c_path.filename().string();

    if (filename != "particles.material") {
        return false;
    }

    std::vector<std::string> patterns = {
        "materials/particles.material",
        "/materials/particles.material",
        "resource_packs/vanilla/materials/particles.material",
        "assets/resource_packs/vanilla/materials/particles.material",
        "vanilla/materials/particles.material",
        "assets/materials/particles.material"
    };

    for (const auto& pattern : patterns) {
        if (path_str.find(pattern) != std::string::npos ||
            (path_str.size() >= pattern.size() &&
             path_str.compare(path_str.size() - pattern.size(), pattern.size(), pattern) == 0)) {
            return true;
        }
    }

    return false;
}

bool is_particles_file(const std::filesystem::path& c_path) {
    std::string path_str = c_path.string();

    if (!c_path.has_filename()) {
        return false;
    }

    std::string filename = c_path.filename().string();

    if (filename != "Particle.material.bin" &&
        filename != "ParticleForwardPBR.material.bin" &&
        filename != "ParticlePrepass.material.bin") {
        return false;
    }

    std::vector<std::string> patterns = {
        "materials/Particle.material.bin",
        "/materials/Particle.material.bin",
        "resource_packs/vanilla/materials/Particle.material.bin",
        "assets/resource_packs/vanilla/materials/Particle.material.bin",
        "vanilla/materials/Particle.material.bin",
        "assets/materials/Particle.material.bin",

        "materials/ParticleForwardPBR.material.bin",
        "/materials/ParticleForwardPBR.material.bin",
        "resource_packs/vanilla/materials/ParticleForwardPBR.material.bin",
        "assets/resource_packs/vanilla/materials/ParticleForwardPBR.material.bin",
        "vanilla/materials/ParticleForwardPBR.material.bin",
        "assets/materials/ParticleForwardPBR.material.bin",

        "materials/ParticlePrepass.material.bin",
        "/materials/ParticlePrepass.material.bin",
        "resource_packs/vanilla/materials/ParticlePrepass.material.bin",
        "assets/resource_packs/vanilla/materials/ParticlePrepass.material.bin",
        "vanilla/materials/ParticlePrepass.material.bin",
        "assets/materials/ParticlePrepass.material.bin"
    };

    for (const auto& pattern : patterns) {
        if (path_str.find(pattern) != std::string::npos ||
            (path_str.size() >= pattern.size() &&
             path_str.compare(path_str.size() - pattern.size(), pattern.size(), pattern) == 0)) {
            return true;
        }
    }

    return false;
}

static AAsset* (*orig_AAssetManager_open)(AAssetManager*, const char*, int) = nullptr;

static AAsset* my_AAssetManager_open(AAssetManager* mgr, const char* name, int mode) {
   std::string sname(name);
   std::filesystem::path fpath(sname);
   
   if(is_particles_file(fpath)) {
      VirtualAssets_BlockFile(name);
      return orig_AAssetManager_open(mgr, "", mode);
   }
   
   if(is_particles_material_file(fpath)) {
      VirtualAssets_AddTextFile(name, PARTICLES_MATERIAL);
      return orig_AAssetManager_open(mgr, "", mode);
   }
   
    return orig_AAssetManager_open(mgr, name, mode);
}

hook_handle* g_hook = nullptr;

__attribute__((constructor))
void StartUp() {
    void* lib = dlopen("libminecraftpe.so", RTLD_NOW);
    if (!lib) {
        void* lib = dlopen("libminecraftpe.so", RTLD_LAZY);
    }
    if (!lib) return;
    void* sym = dlsym(lib, "AAssetManager_open");
    if (!sym) return;
    
    g_hook = hook_addr(
      sym,
      (void*)my_AAssetManager_open,
      (void**)&orig_AAssetManager_open,
      GPWN_AARCH64_MICROHOOK
    );
}

__attribute__((destructor))
void Shutdown() {
    if (g_hook) {
      rm_hook(g_hook);
    }
}