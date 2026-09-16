rule TTP_XOR_WriteProcessMemory_3ab9 {
  strings:
    $key_3ab9 = { 6d cb [2] 5f e9 [2] 59 dc [2] 77 dc [2] 48 c0 }

  condition:
    any of them
}