rule TTP_XOR_WriteProcessMemory_f60a {
  strings:
    $key_f60a = { a1 78 [2] 93 5a [2] 95 6f [2] bb 6f [2] 84 73 }

  condition:
    any of them
}