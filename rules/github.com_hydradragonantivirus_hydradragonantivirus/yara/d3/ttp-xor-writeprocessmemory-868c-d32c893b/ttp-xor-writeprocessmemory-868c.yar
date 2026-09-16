rule TTP_XOR_WriteProcessMemory_868c {
  strings:
    $key_868c = { d1 fe [2] e3 dc [2] e5 e9 [2] cb e9 [2] f4 f5 }

  condition:
    any of them
}