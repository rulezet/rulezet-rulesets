rule TTP_XOR_WriteProcessMemory_71b9 {
  strings:
    $key_71b9 = { 26 cb [2] 14 e9 [2] 12 dc [2] 3c dc [2] 03 c0 }

  condition:
    any of them
}