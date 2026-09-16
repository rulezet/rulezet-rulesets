rule TTP_XOR_WriteProcessMemory_d33f {
  strings:
    $key_d33f = { 84 4d [2] b6 6f [2] b0 5a [2] 9e 5a [2] a1 46 }

  condition:
    any of them
}