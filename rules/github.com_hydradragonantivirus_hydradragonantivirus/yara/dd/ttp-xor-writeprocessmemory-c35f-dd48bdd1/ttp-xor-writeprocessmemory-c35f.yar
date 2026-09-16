rule TTP_XOR_WriteProcessMemory_c35f {
  strings:
    $key_c35f = { 94 2d [2] a6 0f [2] a0 3a [2] 8e 3a [2] b1 26 }

  condition:
    any of them
}