rule TTP_XOR_WriteProcessMemory_d16f {
  strings:
    $key_d16f = { 86 1d [2] b4 3f [2] b2 0a [2] 9c 0a [2] a3 16 }

  condition:
    any of them
}