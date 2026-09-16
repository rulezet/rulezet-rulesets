rule TTP_XOR_WriteProcessMemory_468c {
  strings:
    $key_468c = { 11 fe [2] 23 dc [2] 25 e9 [2] 0b e9 [2] 34 f5 }

  condition:
    any of them
}