rule TTP_XOR_WriteProcessMemory_e57a {
  strings:
    $key_e57a = { b2 08 [2] 80 2a [2] 86 1f [2] a8 1f [2] 97 03 }

  condition:
    any of them
}