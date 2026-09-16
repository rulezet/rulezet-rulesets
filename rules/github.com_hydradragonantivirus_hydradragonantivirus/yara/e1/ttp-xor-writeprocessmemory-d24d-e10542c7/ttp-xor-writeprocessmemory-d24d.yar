rule TTP_XOR_WriteProcessMemory_d24d {
  strings:
    $key_d24d = { 85 3f [2] b7 1d [2] b1 28 [2] 9f 28 [2] a0 34 }

  condition:
    any of them
}