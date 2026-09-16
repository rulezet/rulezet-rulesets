rule TTP_XOR_WriteProcessMemory_c31a {
  strings:
    $key_c31a = { 94 68 [2] a6 4a [2] a0 7f [2] 8e 7f [2] b1 63 }

  condition:
    any of them
}