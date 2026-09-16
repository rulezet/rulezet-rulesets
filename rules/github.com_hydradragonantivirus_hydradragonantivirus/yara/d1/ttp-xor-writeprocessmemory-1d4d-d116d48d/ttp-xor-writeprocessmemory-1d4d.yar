rule TTP_XOR_WriteProcessMemory_1d4d {
  strings:
    $key_1d4d = { 4a 3f [2] 78 1d [2] 7e 28 [2] 50 28 [2] 6f 34 }

  condition:
    any of them
}