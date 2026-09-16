rule TTP_XOR_WriteProcessMemory_c56f {
  strings:
    $key_c56f = { 92 1d [2] a0 3f [2] a6 0a [2] 88 0a [2] b7 16 }

  condition:
    any of them
}