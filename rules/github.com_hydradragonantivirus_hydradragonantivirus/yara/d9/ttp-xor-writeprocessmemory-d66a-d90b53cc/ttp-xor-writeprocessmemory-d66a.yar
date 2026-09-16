rule TTP_XOR_WriteProcessMemory_d66a {
  strings:
    $key_d66a = { 81 18 [2] b3 3a [2] b5 0f [2] 9b 0f [2] a4 13 }

  condition:
    any of them
}