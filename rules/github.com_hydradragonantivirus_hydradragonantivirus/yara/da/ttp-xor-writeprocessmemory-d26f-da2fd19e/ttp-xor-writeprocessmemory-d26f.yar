rule TTP_XOR_WriteProcessMemory_d26f {
  strings:
    $key_d26f = { 85 1d [2] b7 3f [2] b1 0a [2] 9f 0a [2] a0 16 }

  condition:
    any of them
}