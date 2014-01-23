#include "string.h"
#include "stdio.h"
#include "malloc.h"

char *readSegment(FILE *file);
int initializeMacToBrand(void);
char *identifyBrand(char *mac);
int freeMacToBrand(void);