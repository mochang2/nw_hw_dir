// https://gitlab.com/gilgil/sns/-/wikis/byte-order/byte-order
// https://gitlab.com/gilgil/sns/-/wikis/byte-order/report-add-nbo
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t fileread(char*);

int main(int argc, char **argv)
{
    if (argc != 3){
        fprintf(stderr, "Input three file names.\n");
        return -1;
    }
    uint32_t f1, f2, result;
    f1 = fileread(argv[1]);
    f2 = fileread(argv[2]);
    result = f1 + f2;

    printf("%u(0x%3x) + %u(0x%3x) = %u(0x%3x)",
           f1, f1, f2, f2, result, result);
    return 0;
}

uint32_t fileread(char* filename){
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL){ // try file reading
        fprintf(stderr, "File does not exist.\n");
        return -1;
    }

    int f_size;
    uint32_t filecontent;

    fseek(fp, 0, SEEK_END); // move fp to the end
    f_size = ftell(fp);     // measure input data size
    fseek(fp, 0, SEEK_SET); // movd fp to the start again
    fread(&filecontent, f_size, 1, fp); //fscanf() reads text data. fread() reads binary data.

    filecontent = ntohl(filecontent);

    fclose(fp);

    return filecontent;
}
