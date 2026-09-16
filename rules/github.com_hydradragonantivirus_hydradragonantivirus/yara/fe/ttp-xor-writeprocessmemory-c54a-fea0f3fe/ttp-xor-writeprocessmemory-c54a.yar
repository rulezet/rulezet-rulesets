rule TTP_XOR_WriteProcessMemory_c54a {
  strings:
    $key_c54a = { 92 38 [2] a0 1a [2] a6 2f [2] 88 2f [2] b7 33 }

  condition:
    any of them
}