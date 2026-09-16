rule TTP_XOR_WriteProcessMemory_c11f {
  strings:
    $key_c11f = { 96 6d [2] a4 4f [2] a2 7a [2] 8c 7a [2] b3 66 }

  condition:
    any of them
}