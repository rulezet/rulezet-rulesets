rule TTP_XOR_WriteProcessMemory_6fb9 {
  strings:
    $key_6fb9 = { 38 cb [2] 0a e9 [2] 0c dc [2] 22 dc [2] 1d c0 }

  condition:
    any of them
}