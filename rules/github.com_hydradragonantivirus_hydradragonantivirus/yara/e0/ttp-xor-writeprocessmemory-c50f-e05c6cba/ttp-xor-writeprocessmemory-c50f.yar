rule TTP_XOR_WriteProcessMemory_c50f {
  strings:
    $key_c50f = { 92 7d [2] a0 5f [2] a6 6a [2] 88 6a [2] b7 76 }

  condition:
    any of them
}