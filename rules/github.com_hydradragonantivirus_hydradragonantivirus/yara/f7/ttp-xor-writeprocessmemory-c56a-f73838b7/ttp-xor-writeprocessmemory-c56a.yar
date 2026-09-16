rule TTP_XOR_WriteProcessMemory_c56a {
  strings:
    $key_c56a = { 92 18 [2] a0 3a [2] a6 0f [2] 88 0f [2] b7 13 }

  condition:
    any of them
}