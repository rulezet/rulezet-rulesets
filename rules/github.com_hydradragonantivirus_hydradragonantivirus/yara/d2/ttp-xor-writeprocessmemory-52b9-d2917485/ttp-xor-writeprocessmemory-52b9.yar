rule TTP_XOR_WriteProcessMemory_52b9 {
  strings:
    $key_52b9 = { 05 cb [2] 37 e9 [2] 31 dc [2] 1f dc [2] 20 c0 }

  condition:
    any of them
}