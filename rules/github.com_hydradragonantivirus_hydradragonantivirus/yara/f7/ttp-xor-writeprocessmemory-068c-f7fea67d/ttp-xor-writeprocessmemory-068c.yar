rule TTP_XOR_WriteProcessMemory_068c {
  strings:
    $key_068c = { 51 fe [2] 63 dc [2] 65 e9 [2] 4b e9 [2] 74 f5 }

  condition:
    any of them
}