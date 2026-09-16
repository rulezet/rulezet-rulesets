rule TTP_XOR_WriteProcessMemory_f72a {
  strings:
    $key_f72a = { a0 58 [2] 92 7a [2] 94 4f [2] ba 4f [2] 85 53 }

  condition:
    any of them
}