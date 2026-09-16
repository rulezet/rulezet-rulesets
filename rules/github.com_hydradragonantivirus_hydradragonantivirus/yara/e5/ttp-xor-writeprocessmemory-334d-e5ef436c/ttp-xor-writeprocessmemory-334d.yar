rule TTP_XOR_WriteProcessMemory_334d {
  strings:
    $key_334d = { 64 3f [2] 56 1d [2] 50 28 [2] 7e 28 [2] 41 34 }

  condition:
    any of them
}