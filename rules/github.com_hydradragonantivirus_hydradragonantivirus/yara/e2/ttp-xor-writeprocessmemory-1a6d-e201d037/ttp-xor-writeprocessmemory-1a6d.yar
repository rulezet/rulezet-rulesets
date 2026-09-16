rule TTP_XOR_WriteProcessMemory_1a6d {
  strings:
    $key_1a6d = { 4d 1f [2] 7f 3d [2] 79 08 [2] 57 08 [2] 68 14 }

  condition:
    any of them
}