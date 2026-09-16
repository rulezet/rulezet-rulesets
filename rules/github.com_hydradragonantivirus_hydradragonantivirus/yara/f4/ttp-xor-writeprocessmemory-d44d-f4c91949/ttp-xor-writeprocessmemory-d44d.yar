rule TTP_XOR_WriteProcessMemory_d44d {
  strings:
    $key_d44d = { 83 3f [2] b1 1d [2] b7 28 [2] 99 28 [2] a6 34 }

  condition:
    any of them
}