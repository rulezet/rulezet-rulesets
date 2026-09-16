rule TTP_XOR_WriteProcessMemory_f7ce {
  strings:
    $key_f7ce = { a0 bc [2] 92 9e [2] 94 ab [2] ba ab [2] 85 b7 }

  condition:
    any of them
}