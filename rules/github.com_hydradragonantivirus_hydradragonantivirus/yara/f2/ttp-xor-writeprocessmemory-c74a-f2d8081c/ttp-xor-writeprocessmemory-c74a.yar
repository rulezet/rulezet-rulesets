rule TTP_XOR_WriteProcessMemory_c74a {
  strings:
    $key_c74a = { 90 38 [2] a2 1a [2] a4 2f [2] 8a 2f [2] b5 33 }

  condition:
    any of them
}