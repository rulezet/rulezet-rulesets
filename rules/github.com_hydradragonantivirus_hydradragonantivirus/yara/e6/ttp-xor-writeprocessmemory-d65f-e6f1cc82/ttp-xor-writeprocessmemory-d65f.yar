rule TTP_XOR_WriteProcessMemory_d65f {
  strings:
    $key_d65f = { 81 2d [2] b3 0f [2] b5 3a [2] 9b 3a [2] a4 26 }

  condition:
    any of them
}