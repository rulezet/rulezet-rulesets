rule TTP_XOR_WriteProcessMemory_d72a {
  strings:
    $key_d72a = { 80 58 [2] b2 7a [2] b4 4f [2] 9a 4f [2] a5 53 }

  condition:
    any of them
}