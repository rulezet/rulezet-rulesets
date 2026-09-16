rule TTP_XOR_WriteProcessMemory_f6ea {
  strings:
    $key_f6ea = { a1 98 [2] 93 ba [2] 95 8f [2] bb 8f [2] 84 93 }

  condition:
    any of them
}