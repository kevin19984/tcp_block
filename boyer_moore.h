#pragma once

void computeJump(unsigned char* pattern, int patternlen, int* jump);
int BoyerMooreHorspool(unsigned char* text, int textlen, unsigned char* pattern, int patternlen, int* jump);

