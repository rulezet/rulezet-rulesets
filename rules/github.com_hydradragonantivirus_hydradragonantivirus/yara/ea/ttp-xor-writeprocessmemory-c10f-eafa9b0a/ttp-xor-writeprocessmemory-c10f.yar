rule TTP_XOR_WriteProcessMemory_c10f {
  strings:
    $key_c10f = { 96 7d [2] a4 5f [2] a2 6a [2] 8c 6a [2] b3 76 }

  condition:
    any of them
}