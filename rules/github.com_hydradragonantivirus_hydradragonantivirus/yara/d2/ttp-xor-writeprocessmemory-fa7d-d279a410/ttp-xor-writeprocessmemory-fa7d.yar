rule TTP_XOR_WriteProcessMemory_fa7d {
  strings:
    $key_fa7d = { ad 0f [2] 9f 2d [2] 99 18 [2] b7 18 [2] 88 04 }

  condition:
    any of them
}