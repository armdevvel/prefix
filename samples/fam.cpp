#include "paths.h"

#include <stdio.h>
#include <assert.h>

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    // TODO add switches to display:
    // > all basic paths;
    // > all known paths.
    
    printf("Displaying known path types and values\n================\n");
    fflush(stdout);
    fixpre::EnumerateKnownBasePaths([](enum fixpre_known_path kind, const std::string& path) {
        const char* desc = fixpre_explain(kind);
        printf("%08x: %s (%s)\n", kind, path.c_str(), desc);
    });

    printf("\nModi... fire! Now the complete cache\n================\n");
    fflush(stdout);
    fixpre::EnumerateCachedPaths([](enum fixpre_known_path kind, const std::string& suffix, const std::string& path) {
        printf("%08x/%s: %s\n", kind, suffix.c_str(), path.c_str());
    });
}
