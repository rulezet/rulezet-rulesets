rule TTP_XOR_WriteProcessMemory_f63f {
  strings:
    $key_f63f = { a1 4d [2] 93 6f [2] 95 5a [2] bb 5a [2] 84 46 }

  condition:
    any of them
}