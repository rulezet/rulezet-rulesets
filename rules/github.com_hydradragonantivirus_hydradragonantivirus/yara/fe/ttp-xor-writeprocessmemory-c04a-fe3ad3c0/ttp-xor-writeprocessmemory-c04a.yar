rule TTP_XOR_WriteProcessMemory_c04a {
  strings:
    $key_c04a = { 97 38 [2] a5 1a [2] a3 2f [2] 8d 2f [2] b2 33 }

  condition:
    any of them
}