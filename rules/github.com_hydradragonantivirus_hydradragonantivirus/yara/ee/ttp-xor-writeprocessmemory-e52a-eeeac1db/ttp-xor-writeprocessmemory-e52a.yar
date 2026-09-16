rule TTP_XOR_WriteProcessMemory_e52a {
  strings:
    $key_e52a = { b2 58 [2] 80 7a [2] 86 4f [2] a8 4f [2] 97 53 }

  condition:
    any of them
}