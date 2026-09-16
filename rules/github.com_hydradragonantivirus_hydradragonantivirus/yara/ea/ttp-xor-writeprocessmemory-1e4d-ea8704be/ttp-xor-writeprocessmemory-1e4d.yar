rule TTP_XOR_WriteProcessMemory_1e4d {
  strings:
    $key_1e4d = { 49 3f [2] 7b 1d [2] 7d 28 [2] 53 28 [2] 6c 34 }

  condition:
    any of them
}