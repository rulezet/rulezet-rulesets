rule TTP_XOR_WriteProcessMemory_678c {
  strings:
    $key_678c = { 30 fe [2] 02 dc [2] 04 e9 [2] 2a e9 [2] 15 f5 }

  condition:
    any of them
}