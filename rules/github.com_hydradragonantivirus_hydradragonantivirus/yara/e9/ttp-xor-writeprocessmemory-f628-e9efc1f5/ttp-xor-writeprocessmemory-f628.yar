rule TTP_XOR_WriteProcessMemory_f628 {
  strings:
    $key_f628 = { a1 5a [2] 93 78 [2] 95 4d [2] bb 4d [2] 84 51 }

  condition:
    any of them
}