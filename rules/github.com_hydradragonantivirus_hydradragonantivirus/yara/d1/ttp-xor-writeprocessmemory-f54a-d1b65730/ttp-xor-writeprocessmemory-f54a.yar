rule TTP_XOR_WriteProcessMemory_f54a {
  strings:
    $key_f54a = { a2 38 [2] 90 1a [2] 96 2f [2] b8 2f [2] 87 33 }

  condition:
    any of them
}