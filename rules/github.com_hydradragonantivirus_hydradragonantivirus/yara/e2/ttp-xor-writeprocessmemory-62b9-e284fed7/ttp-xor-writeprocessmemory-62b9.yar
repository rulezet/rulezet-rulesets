rule TTP_XOR_WriteProcessMemory_62b9 {
  strings:
    $key_62b9 = { 35 cb [2] 07 e9 [2] 01 dc [2] 2f dc [2] 10 c0 }

  condition:
    any of them
}