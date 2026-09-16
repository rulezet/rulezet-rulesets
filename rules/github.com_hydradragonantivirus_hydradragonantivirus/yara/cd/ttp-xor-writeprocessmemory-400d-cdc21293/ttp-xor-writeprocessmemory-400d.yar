rule TTP_XOR_WriteProcessMemory_400d {
  strings:
    $key_400d = { 17 7f [2] 25 5d [2] 23 68 [2] 0d 68 [2] 32 74 }

  condition:
    any of them
}