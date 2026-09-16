rule TTP_XOR_WriteProcessMemory_96f5 {
  strings:
    $key_96f5 = { c1 87 [2] f3 a5 [2] f5 90 [2] db 90 [2] e4 8c }

  condition:
    any of them
}