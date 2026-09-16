rule TTP_XOR_WriteProcessMemory_f3ce {
  strings:
    $key_f3ce = { a4 bc [2] 96 9e [2] 90 ab [2] be ab [2] 81 b7 }

  condition:
    any of them
}