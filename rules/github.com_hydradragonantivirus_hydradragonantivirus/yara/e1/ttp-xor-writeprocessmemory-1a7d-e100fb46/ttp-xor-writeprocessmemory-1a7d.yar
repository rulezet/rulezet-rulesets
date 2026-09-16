rule TTP_XOR_WriteProcessMemory_1a7d {
  strings:
    $key_1a7d = { 4d 0f [2] 7f 2d [2] 79 18 [2] 57 18 [2] 68 04 }

  condition:
    any of them
}