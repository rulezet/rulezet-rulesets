rule TTP_XOR_WriteProcessMemory_d75a {
  strings:
    $key_d75a = { 80 28 [2] b2 0a [2] b4 3f [2] 9a 3f [2] a5 23 }

  condition:
    any of them
}