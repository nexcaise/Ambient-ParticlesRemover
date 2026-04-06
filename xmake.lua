set_project("ParticlesRemover") -- mod name
set_version("1.0.0") -- mod version

set_languages("cxx23")

add_rules("mode.release")

add_repositories("xmake-repo https://github.com/xmake-io/xmake-repo.git")

target("ParticlesRemover") -- mod name
    set_kind("shared")
    add_links("log") -- add links, to included the nise api into the mod
    add_files("src/*.cpp", "src/gamepwnage/*.c") -- add all cpp files in src folder, for compile the mod
	add_includedirs("src/gamepwnage", {public = true}) -- gamepwnage api