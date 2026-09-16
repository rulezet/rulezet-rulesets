rule TTP_XOR_WriteProcessMemory_d42a {
  strings:
    $key_d42a = { 83 58 [2] b1 7a [2] b7 4f [2] 99 4f [2] a6 53 }

  condition:
    any of them
}