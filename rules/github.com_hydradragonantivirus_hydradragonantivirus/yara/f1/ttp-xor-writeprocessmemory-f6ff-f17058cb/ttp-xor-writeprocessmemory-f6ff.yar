rule TTP_XOR_WriteProcessMemory_f6ff {
  strings:
    $key_f6ff = { a1 8d [2] 93 af [2] 95 9a [2] bb 9a [2] 84 86 }

  condition:
    any of them
}