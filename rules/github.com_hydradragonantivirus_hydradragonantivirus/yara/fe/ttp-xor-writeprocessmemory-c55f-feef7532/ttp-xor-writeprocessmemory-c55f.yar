rule TTP_XOR_WriteProcessMemory_c55f {
  strings:
    $key_c55f = { 92 2d [2] a0 0f [2] a6 3a [2] 88 3a [2] b7 26 }

  condition:
    any of them
}