#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings (32 chars + null)


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    if (plaintext == NULL || hashFilename == NULL) return NULL;

    // Hash the plaintext
    char *digest = md5(plaintext, (int)strlen(plaintext));
    if (digest == NULL) {
        fprintf(stderr, "md5() failed for word: %s\n", plaintext);
        return NULL;
    }

    // Open the hash file
    FILE *hf = fopen(hashFilename, "r");
    if (hf == NULL) {
        perror("Error opening hash file in tryWord");
        free(digest);
        return NULL;
    }

    // Loop through the hash file, one line at a time.
    char line[HASH_LEN + 16];
    char *found = NULL;
    while (fgets(line, sizeof(line), hf)) {
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        line[strcspn(line, "\r\n")] = '\0';  // trim newline

        if (line[0] == '\0') continue;

        // If there is a match, you'll return the hash.
        // If not, return NULL.
        if (strcmp(digest, line) == 0) {
            found = strdup(line); // caller will free this
            break;
        }
    }

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(hf);
    free(digest);

    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    return found;
}


int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // These two lines exist for testing. When you have
    // tryWord working, it should display the hash for "hello",
    // which is 5d41402abc4b2a76b9719d911017c592.
    // Then you can remove these two lines and complete the rest
    // of the main function below.
    char *hashFile = argv[1];
    char *dictFile = argv[2];

    // Open the dictionary file for reading.
    FILE *df = fopen(dictFile, "r");
    if (df == NULL) {
        perror("Error opening dictionary file");
        return 1;
    }

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    size_t capacity = 64;
    size_t crackedCount = 0;
    char **crackedHashes = malloc(capacity * sizeof(char *));
    if (!crackedHashes) {
        fprintf(stderr, "Memory allocation error\n");
        fclose(df);
        return 1;
    }
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    char word[PASS_LEN + 8];

    // For each dictionary word, pass it to tryWord, which will attempt to match it against the hashes in the hash_file. 
    while (fgets(word, sizeof(word), df)) {
        /* trim newline */
        word[strcspn(word, "\r\n")] = '\0';
        if (word[0] == '\0') continue;

        // If we got a match, display the hash and the word.
        char *match = tryWord(word, hashFile);
        if (match != NULL) {
            // Check if we've already printed this cracked hash.
            int already = 0;
            for (size_t i = 0; i < crackedCount; ++i) {
                if (strcmp(crackedHashes[i], match) == 0) {
                    already = 1;
                    break;
                }
            }

            if (!already) {
                printf("%s %s\n", match, word);

                // store the match. 
                if (crackedCount >= capacity) {
                    capacity *= 2;
                    char **tmp = realloc(crackedHashes, capacity * sizeof(char *));
                    if (!tmp) {
                        fprintf(stderr, "Memory allocation error\n");
                        free(match);
                        break;
                    }
                    crackedHashes = tmp;
                }
                crackedHashes[crackedCount++] = match; // keep ownership of match.
            } else {
                free(match); // duplicate match not needed.
            }
        } /* end if match != NULL */
    } /* end while fgets */

    // Close the dictionary file.
    fclose(df);

    // Display the number of hashes that were cracked.
    printf("%zu hashes cracked!\n", crackedCount);

    // Free up any malloc'd memory?
    for (size_t i = 0; i < crackedCount; ++i) free(crackedHashes[i]);
    free(crackedHashes);

    return 0;
}
