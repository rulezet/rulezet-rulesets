rule TTP_XOR_WriteProcessMemory_92b9 {
  strings:
    $key_92b9 = { c5 cb [2] f7 e9 [2] f1 dc [2] df dc [2] e0 c0 }

  condition:
    any of them
}