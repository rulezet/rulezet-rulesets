rule TTP_XOR_WriteProcessMemory_5c4d {
  strings:
    $key_5c4d = { 0b 3f [2] 39 1d [2] 3f 28 [2] 11 28 [2] 2e 34 }

  condition:
    any of them
}