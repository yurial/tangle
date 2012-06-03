#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/mman.h>

#include "tangle_hash.h"

int hash_size = 256 / 8;
const char* hash_file = NULL;

const static char options[] = "h263571";
const static struct option long_options[] = {
    { "help",   0, 0, 'h' },
    { "224",    0, 0, '2' },
    { "256",    0, 0, '6' },
    { "384",    0, 0, '3' },
    { "512",    0, 0, '5' },
    { "768",    0, 0, '7' },
    { "1024",   0, 0, '1' },
    { NULL,     0, 0,  0  }
    };

void params(int argc, char* argv[]);
void help(FILE* os, int argc, char* argv[]);
void print_hash(const unsigned char* hash, size_t hashsize);

void params(int argc, char* argv[])
{
int option;
int option_index;
do
    {
    option = getopt_long( argc, argv, options, long_options, &option_index );
    switch ( option )
        {
        case -1:
            break;
        case 'h':
            help( stdout, argc, argv);
            exit( EXIT_SUCCESS );
        case '2':
            hash_size = 224 / 8;
            break;
        case '6':
            hash_size = 256 / 8;
            break;
        case '3':
            hash_size = 338 / 8;
            break;
        case '5':
            hash_size = 512 / 8;
            break;
        case '7':
            hash_size = 768 / 8;
            break;
        case '1':
            hash_size = 1024 / 8;
            break;
        case 0:
        case 1:
        case 2:
        default:
            help( stderr, argc, argv );
            exit( EXIT_FAILURE );
        }
    }
while ( -1 != option );

if ( optind < argc )
    {
    hash_file = argv[ optind ];
    }
}

void help(FILE* os, int argc, char* argv[])
{
fprintf( os, "usage: %s [-h|<hashsize>] <file>\n", argv[0] );
fprintf( os, "hashsize:\n" );
fprintf( os, "    --224   -2\n" );
fprintf( os, "    --256   -6 (default)\n" );
fprintf( os, "    --338   -3\n" );
fprintf( os, "    --512   -5\n" );
fprintf( os, "    --768   -7\n" );
fprintf( os, "    --1024  -1\n" );
}

void print_hash(const unsigned char* hash, size_t hashsize)
{
while ( hashsize )
    {
    fprintf( stdout, "%02x", *hash );
    --hashsize;
    ++hash;
    }
}

int main(int argc, char* argv[])
{
char hash[ 1024/8 ];

hash_file = argv[0];
params( argc, argv );

int fd = open( hash_file, 0 );
if ( -1 == fd )
    {
    perror( NULL );
    return EXIT_FAILURE;
    }
off_t data_size = lseek( fd, 0, SEEK_END );
if ( -1 == data_size )
    {
    perror ( NULL );
    return EXIT_FAILURE;
    }
void* data = mmap( NULL, data_size, PROT_READ, MAP_SHARED | MAP_NORESERVE, fd, 0 );
if ( MAP_FAILED == data )
    {
    perror( NULL );
    return EXIT_FAILURE;
    }
Hash( hash_size << 3, data, data_size << 3, hash );
munmap( data, data_size );
close( fd );

print_hash( hash, hash_size );
fprintf( stdout, "\n" );
return EXIT_SUCCESS;
}

