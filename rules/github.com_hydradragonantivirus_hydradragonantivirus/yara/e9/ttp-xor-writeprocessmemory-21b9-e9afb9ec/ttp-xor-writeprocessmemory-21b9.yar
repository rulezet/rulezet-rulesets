rule TTP_XOR_WriteProcessMemory_21b9 {
  strings:
    $key_21b9 = { 76 cb [2] 44 e9 [2] 42 dc [2] 6c dc [2] 53 c0 }

  condition:
    any of them
}