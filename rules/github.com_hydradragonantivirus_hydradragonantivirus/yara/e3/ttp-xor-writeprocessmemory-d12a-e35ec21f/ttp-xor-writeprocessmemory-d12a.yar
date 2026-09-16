rule TTP_XOR_WriteProcessMemory_d12a {
  strings:
    $key_d12a = { 86 58 [2] b4 7a [2] b2 4f [2] 9c 4f [2] a3 53 }

  condition:
    any of them
}