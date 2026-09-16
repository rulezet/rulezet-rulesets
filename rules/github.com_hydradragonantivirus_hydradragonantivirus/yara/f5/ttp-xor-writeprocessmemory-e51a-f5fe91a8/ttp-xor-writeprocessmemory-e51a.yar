rule TTP_XOR_WriteProcessMemory_e51a {
  strings:
    $key_e51a = { b2 68 [2] 80 4a [2] 86 7f [2] a8 7f [2] 97 63 }

  condition:
    any of them
}