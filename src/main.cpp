#include <android/asset_manager.h>
#include <string>
#include <vector>
#include <filesystem>
#include "inlinehook.h"
#include <dlfcn.h>
#include <cstdint>

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
   
   if(is_particles_file(fpath)) return orig_AAssetManager_open(mgr, "", mode);
   
   if(is_particles_material_file(fpath)) return orig_AAssetManager_open(mgr, "", mode);
   
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