rule TTP_XOR_WriteProcessMemory_c13a {
  strings:
    $key_c13a = { 96 48 [2] a4 6a [2] a2 5f [2] 8c 5f [2] b3 43 }

  condition:
    any of them
}