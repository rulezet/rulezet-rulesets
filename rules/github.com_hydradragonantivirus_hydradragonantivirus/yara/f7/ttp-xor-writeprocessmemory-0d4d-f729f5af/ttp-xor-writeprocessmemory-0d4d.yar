rule TTP_XOR_WriteProcessMemory_0d4d {
  strings:
    $key_0d4d = { 5a 3f [2] 68 1d [2] 6e 28 [2] 40 28 [2] 7f 34 }

  condition:
    any of them
}