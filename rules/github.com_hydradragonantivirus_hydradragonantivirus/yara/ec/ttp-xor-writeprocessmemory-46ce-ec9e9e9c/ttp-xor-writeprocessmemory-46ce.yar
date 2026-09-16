rule TTP_XOR_WriteProcessMemory_46ce {
  strings:
    $key_46ce = { 11 bc [2] 23 9e [2] 25 ab [2] 0b ab [2] 34 b7 }

  condition:
    any of them
}