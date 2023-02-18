#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/mman.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<string.h>
#include<fcntl.h>

int main(int argc,char **argv)
{
  unsigned long off;
  unsigned char *map_base;
  //FILE *f;
  int fd;

  off = strtol(argv[1],NULL,16);
  fd = open ("/dev/mem", O_RDWR | O_SYNC);

  if (fd == -1)
  {
      printf ("open /dev/mem fail!\n");
      return (-1);
  }

  map_base = mmap (NULL, 0xff, PROT_READ | PROT_WRITE, MAP_SHARED, fd,off);

  if (map_base == 0)

    {

      printf ("NULL pointer!\n");

    }

  else

    {

      printf ("map Successfull!\n");

    }

 

  unsigned long addr;

  unsigned char content;

 

  int i = 0;

  for (; i < 0xf; ++i)

    {

      addr = (unsigned long) (map_base + i);

      content = map_base[i];

      printf ("address: 0x%lx   value: 0x%x\t\t", addr,

              (unsigned int) content);

 
/*
      map_base[i] = (unsigned char) i;

      content = map_base[i];

      printf ("address: 0x%lx   value: 0x%x\t\t", addr,

              (unsigned int) content);

 

      map_base[i] = (unsigned char) i;

      content = map_base[i];

      printf ("address: 0x%lx   new value: 0x%x\n", addr,

              (unsigned int) content);*/

    }
    
    map_base[0] = (unsigned char) 'b';

      content = map_base[0];

      printf ("change:value: 0x%x\t\t", 

              (unsigned int) content);

 

  close (fd);

  munmap (map_base, 0xff);

  return (1);

}
