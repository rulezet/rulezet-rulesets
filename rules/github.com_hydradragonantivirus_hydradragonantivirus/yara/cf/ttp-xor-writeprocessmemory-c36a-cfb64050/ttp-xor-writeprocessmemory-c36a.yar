rule TTP_XOR_WriteProcessMemory_c36a {
  strings:
    $key_c36a = { 94 18 [2] a6 3a [2] a0 0f [2] 8e 0f [2] b1 13 }

  condition:
    any of them
}