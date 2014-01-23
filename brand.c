#include "string.h"
#include "stdio.h"
#include "malloc.h"
#include "brand.h"

static char* macToBrand[18971][2];
char* UNKNOWN_BRAND = "Unknown Brand";

int initializeMacToBrand(void) {
	int i = 0;
	FILE * fp;
	char * line = NULL;

	fp = fopen("parse.txt", "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not find parse.txt!");
		exit(EXIT_FAILURE);

	}

	for (i = 0; i < 18971; i++) {
		macToBrand[i][0] = readSegment(fp);
		macToBrand[i][1] = readSegment(fp);
	}
}

int freeMacToBrand(void) {
	int i;
	for (i = 0; i < 18971; i++) {
		free(macToBrand[i][0]);
		free(macToBrand[i][1]);
	}
	return 1;
}




char *readSegment(FILE *file) {

    if (file == NULL) {
        printf("Error: file pointer is null.");
        exit(1);
    }

    int maximumLineLength = 128;
    char *lineBuffer = (char *)malloc(sizeof(char) * maximumLineLength);

    if (lineBuffer == NULL) {
        printf("Error allocating memory for line buffer.");
        exit(1);
    }

    char ch = getc(file);
    int count = 0;

    if (ch == EOF) {
    	return NULL;
    }

    while ((ch != '\\') && (ch != '\n') && (ch != EOF)) {
        if (count == maximumLineLength) {
            maximumLineLength += 128;
            lineBuffer = (char *)realloc(lineBuffer, maximumLineLength);
            if (lineBuffer == NULL) {
                printf("Error reallocating space for line buffer.");
                exit(1);
            }
        }
        lineBuffer[count] = ch;
        count++;

        ch = getc(file);
    }

    lineBuffer[count] = '\0';

    char *line;
    line = (char *)malloc(count + 1);
    strncpy(line, lineBuffer, (count + 1));
    free(lineBuffer);
    
    return line;
}


char *identifyBrand(char *mac) {
	int i = 0;
	for (i = 0; i < 18971; i++) {
		if (strncmp(mac, macToBrand[i][0], 8) == 0) {
			return macToBrand[i][1];
		}
	}
	return UNKNOWN_BRAND;
}
