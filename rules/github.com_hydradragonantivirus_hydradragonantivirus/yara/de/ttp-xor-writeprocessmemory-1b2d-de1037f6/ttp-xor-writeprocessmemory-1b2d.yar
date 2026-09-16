rule TTP_XOR_WriteProcessMemory_1b2d {
  strings:
    $key_1b2d = { 4c 5f [2] 7e 7d [2] 78 48 [2] 56 48 [2] 69 54 }

  condition:
    any of them
}