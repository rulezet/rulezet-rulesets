rule TTP_XOR_WriteProcessMemory_76b9 {
  strings:
    $key_76b9 = { 21 cb [2] 13 e9 [2] 15 dc [2] 3b dc [2] 04 c0 }

  condition:
    any of them
}