rule TTP_XOR_WriteProcessMemory_1a0d {
  strings:
    $key_1a0d = { 4d 7f [2] 7f 5d [2] 79 68 [2] 57 68 [2] 68 74 }

  condition:
    any of them
}