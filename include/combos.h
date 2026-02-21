#pragma once

typedef struct {
    char *username;
    char *password;
} Combo;

extern Combo combos[];
extern int combo_count;

void combos_init(void);
