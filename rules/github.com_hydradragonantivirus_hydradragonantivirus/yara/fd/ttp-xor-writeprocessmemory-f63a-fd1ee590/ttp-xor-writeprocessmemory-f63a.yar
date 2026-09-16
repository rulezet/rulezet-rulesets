rule TTP_XOR_WriteProcessMemory_f63a {
  strings:
    $key_f63a = { a1 48 [2] 93 6a [2] 95 5f [2] bb 5f [2] 84 43 }

  condition:
    any of them
}