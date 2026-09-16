rule TTP_XOR_WriteProcessMemory_0d2d {
  strings:
    $key_0d2d = { 5a 5f [2] 68 7d [2] 6e 48 [2] 40 48 [2] 7f 54 }

  condition:
    any of them
}