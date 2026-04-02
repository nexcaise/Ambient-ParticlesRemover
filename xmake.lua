set_project("ParticlesRemover") -- mod name
set_version("1.0.0") -- mod version

set_languages("cxx23")

add_rules("mode.release")

add_repositories("xmake-repo https://github.com/xmake-io/xmake-repo.git")

--add_requires("nlohmann_json v3.11.3") -- json api for config thats use preloader api

target("ParticlesRemover") -- mod name
    set_kind("shared")
    --add_packages("nlohmann_json")
    --add_linkdirs("libs/arm64-v8a")
    add_linkdirs("niseAPI/libs/arm64-v8a")
    add_links("nise", "log") -- add links, to included the nise api into the mod
    --add_defines("PRELOADER_EXPORT", "MINIAPI_MACRO", "UNICODE")
    add_files("src/*.cpp", "src/gamepwnage/*.c") -- add all cpp files in src folder, for compile the mod

    -- include dirs, for #include {file} works

    --add_includedirs("include", {public = true}) -- preloader api
    --add_includedirs("include/pl", {public = true}) -- preloader api
    add_includedirs("include/gamepwnage", {public = true}) -- gamepwnage api
    add_includedirs("niseAPI/include", {public = true}) -- nise api
