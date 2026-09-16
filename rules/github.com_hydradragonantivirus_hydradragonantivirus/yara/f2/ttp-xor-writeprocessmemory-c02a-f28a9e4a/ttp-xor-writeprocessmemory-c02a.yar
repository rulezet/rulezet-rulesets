rule TTP_XOR_WriteProcessMemory_c02a {
  strings:
    $key_c02a = { 97 58 [2] a5 7a [2] a3 4f [2] 8d 4f [2] b2 53 }

  condition:
    any of them
}