#include <windows.h>
#include <stdio.h>
typedef void (*InitFn)(void);
typedef const char* (*VerFn)(void);
int main(void){
  HMODULE h = LoadLibraryA("dist/widevinecdm.dll");
  if(!h){ printf("LoadLibrary FAILED err=%lu\n", GetLastError()); return 1; }
  InitFn init = (InitFn)GetProcAddress(h, "InitializeCdmModule_4");
  VerFn ver = (VerFn)GetProcAddress(h, "GetCdmVersion");
  void* create = (void*)GetProcAddress(h, "CreateCdmInstance");
  if(!init||!ver||!create){ printf("GetProcAddress FAILED\n"); return 2; }
  init();
  printf("GetCdmVersion: %s\n", ver());
  printf("CreateCdmInstance addr: %p\n", create);
  printf("SMOKE OK\n");
  return 0;
}
