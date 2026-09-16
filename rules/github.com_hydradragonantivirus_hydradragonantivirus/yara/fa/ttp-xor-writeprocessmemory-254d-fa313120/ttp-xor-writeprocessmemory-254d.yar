rule TTP_XOR_WriteProcessMemory_254d {
  strings:
    $key_254d = { 72 3f [2] 40 1d [2] 46 28 [2] 68 28 [2] 57 34 }

  condition:
    any of them
}