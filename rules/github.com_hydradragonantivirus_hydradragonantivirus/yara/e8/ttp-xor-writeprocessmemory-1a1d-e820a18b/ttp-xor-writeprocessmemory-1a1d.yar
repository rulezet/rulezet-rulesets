rule TTP_XOR_WriteProcessMemory_1a1d {
  strings:
    $key_1a1d = { 4d 6f [2] 7f 4d [2] 79 78 [2] 57 78 [2] 68 64 }

  condition:
    any of them
}