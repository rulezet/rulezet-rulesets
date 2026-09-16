rule TTP_XOR_WriteProcessMemory_87b9 {
  strings:
    $key_87b9 = { d0 cb [2] e2 e9 [2] e4 dc [2] ca dc [2] f5 c0 }

  condition:
    any of them
}