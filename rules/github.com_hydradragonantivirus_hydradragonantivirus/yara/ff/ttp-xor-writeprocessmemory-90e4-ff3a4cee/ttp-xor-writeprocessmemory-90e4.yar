rule TTP_XOR_WriteProcessMemory_90e4 {
  strings:
    $key_90e4 = { c7 96 [2] f5 b4 [2] f3 81 [2] dd 81 [2] e2 9d }

  condition:
    any of them
}