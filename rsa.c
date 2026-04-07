#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long long ull;

ull gcd(ull a, ull b) {
    while (b != 0) {
        ull temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

long long extended_gcd(long long a, long long b, long long *x, long long *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }

    long long x1 = 0;
    long long y1 = 0;
    long long g = extended_gcd(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

ull mod_inverse(ull value, ull mod) {
    long long x = 0;
    long long y = 0;
    long long g = extended_gcd((long long)value, (long long)mod, &x, &y);

    if (g != 1) {
        return 0;
    }

    x %= (long long)mod;
    if (x < 0) {
        x += (long long)mod;
    }
    return (ull)x;
}

ull pow_mod(ull base, ull exponent, ull mod) {
    ull result = 1;
    base %= mod;

    while (exponent > 0) {
        if (exponent & 1ULL) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exponent >>= 1ULL;
    }

    return result;
}

int is_prime(ull number) {
    if (number < 2) {
        return 0;
    }
    if (number == 2) {
        return 1;
    }
    if (number % 2 == 0) {
        return 0;
    }

    for (ull i = 3; i * i <= number; i += 2) {
        if (number % i == 0) {
            return 0;
        }
    }
    return 1;
}

ull choose_public_exponent(ull phi) {
    ull common_values[] = {65537ULL, 257ULL, 17ULL, 5ULL, 3ULL};
    size_t candidate_count = sizeof(common_values) / sizeof(common_values[0]);

    for (size_t i = 0; i < candidate_count; ++i) {
        ull e = common_values[i];
        if (e < phi && gcd(e, phi) == 1) {
            return e;
        }
    }

    for (ull e = 3; e < phi; e += 2) {
        if (gcd(e, phi) == 1) {
            return e;
        }
    }

    return 0;
}

void prepare_plaintext_source(const char *plaintext_path) {
    char choice[16];

    printf("Input options:\n");
    printf("1. Use the existing text from plaintext.txt\n");
    printf("2. Enter a new message from the keyboard\n");
    printf("Choose 1 or 2 (default 1): ");

    if (fgets(choice, sizeof(choice), stdin) != NULL && choice[0] == '2') {
        char message[2048];
        FILE *plaintext_output = fopen(plaintext_path, "wb");

        if (plaintext_output == NULL) {
            perror("Error opening plaintext.txt for writing");
            exit(1);
        }

        printf("Enter your message: ");
        if (fgets(message, sizeof(message), stdin) == NULL) {
            message[0] = '\0';
        }

        size_t newline_pos = strcspn(message, "\n");
        message[newline_pos] = '\0';

        fputs(message, plaintext_output);
        fclose(plaintext_output);

        printf("Saved keyboard input to %s\n\n", plaintext_path);
    } else {
        printf("Using text already stored in %s\n\n", plaintext_path);
    }
}

int main(void) {
    const char *plaintext_path = "plaintext.txt";
    const char *ciphertext_path = "ciphertext.txt";
    const char *decoded_path = "decoded.txt";

    ull p = 257ULL;
    ull q = 263ULL;

    if (!is_prime(p) || !is_prime(q)) {
        fprintf(stderr, "Error: p and q must both be prime numbers.\n");
        return 1;
    }

    ull n = p * q;
    ull phi = (p - 1) * (q - 1);

    if (n < (1ULL << 16)) {
        fprintf(stderr, "Error: modulus n must be at least 16 bits.\n");
        return 1;
    }

    ull e = choose_public_exponent(phi);
    if (e == 0) {
        fprintf(stderr, "Error: could not find a valid public exponent e.\n");
        return 1;
    }

    ull d = mod_inverse(e, phi);
    if (d == 0) {
        fprintf(stderr, "Error: could not compute the private exponent d.\n");
        return 1;
    }

    printf("Generated RSA keys and parameters:\n");
    printf("p   = %llu\n", p);
    printf("q   = %llu\n", q);
    printf("n   = %llu\n", n);
    printf("phi = %llu\n", phi);
    printf("Public key  (e, n) = (%llu, %llu)\n", e, n);
    printf("Private key (d, n) = (%llu, %llu)\n\n", d, n);

    prepare_plaintext_source(plaintext_path);

    FILE *plaintext_file = fopen(plaintext_path, "rb");
    if (plaintext_file == NULL) {
        perror("Error opening plaintext.txt");
        return 1;
    }

    FILE *ciphertext_file = fopen(ciphertext_path, "w");
    if (ciphertext_file == NULL) {
        perror("Error opening ciphertext.txt for writing");
        fclose(plaintext_file);
        return 1;
    }

    int ch = 0;
    size_t character_count = 0;

    while ((ch = fgetc(plaintext_file)) != EOF) {
        ull encrypted_value = pow_mod((unsigned char)ch, d, n);
        fprintf(ciphertext_file, "%llu ", encrypted_value);
        character_count++;
    }

    fclose(plaintext_file);
    fclose(ciphertext_file);

    FILE *ciphertext_input = fopen(ciphertext_path, "r");
    if (ciphertext_input == NULL) {
        perror("Error opening ciphertext.txt for reading");
        return 1;
    }

    FILE *decoded_file = fopen(decoded_path, "wb");
    if (decoded_file == NULL) {
        perror("Error opening decoded.txt for writing");
        fclose(ciphertext_input);
        return 1;
    }

    ull encrypted_value = 0;
    while (fscanf(ciphertext_input, "%llu", &encrypted_value) == 1) {
        ull decrypted_value = pow_mod(encrypted_value, e, n);
        fputc((unsigned char)decrypted_value, decoded_file);
    }

    fclose(ciphertext_input);
    fclose(decoded_file);

    printf("Plaintext file read    : %s\n", plaintext_path);
    printf("Ciphertext file written: %s\n", ciphertext_path);
    printf("Decoded file written   : %s\n", decoded_path);
    printf("Characters processed   : %zu\n", character_count);
    printf("\nRSA demonstration completed successfully.\n");

    return 0;
}
