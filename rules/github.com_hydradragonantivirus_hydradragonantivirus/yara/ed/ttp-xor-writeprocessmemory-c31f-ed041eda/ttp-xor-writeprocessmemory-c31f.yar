rule TTP_XOR_WriteProcessMemory_c31f {
  strings:
    $key_c31f = { 94 6d [2] a6 4f [2] a0 7a [2] 8e 7a [2] b1 66 }

  condition:
    any of them
}