rule TTP_XOR_WriteProcessMemory_0e4d {
  strings:
    $key_0e4d = { 59 3f [2] 6b 1d [2] 6d 28 [2] 43 28 [2] 7c 34 }

  condition:
    any of them
}