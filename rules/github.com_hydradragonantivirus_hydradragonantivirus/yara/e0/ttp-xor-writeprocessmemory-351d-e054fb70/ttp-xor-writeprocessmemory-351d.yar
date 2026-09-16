rule TTP_XOR_WriteProcessMemory_351d {
  strings:
    $key_351d = { 62 6f [2] 50 4d [2] 56 78 [2] 78 78 [2] 47 64 }

  condition:
    any of them
}