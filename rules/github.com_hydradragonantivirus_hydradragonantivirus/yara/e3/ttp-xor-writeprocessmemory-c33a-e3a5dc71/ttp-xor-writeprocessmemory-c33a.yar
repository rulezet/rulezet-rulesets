rule TTP_XOR_WriteProcessMemory_c33a {
  strings:
    $key_c33a = { 94 48 [2] a6 6a [2] a0 5f [2] 8e 5f [2] b1 43 }

  condition:
    any of them
}