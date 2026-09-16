rule TTP_XOR_WriteProcessMemory_1fb9 {
  strings:
    $key_1fb9 = { 48 cb [2] 7a e9 [2] 7c dc [2] 52 dc [2] 6d c0 }

  condition:
    any of them
}