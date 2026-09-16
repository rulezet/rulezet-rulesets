rule TTP_XOR_WriteProcessMemory_0c9b {
  strings:
    $key_0c9b = { 5b e9 [2] 69 cb [2] 6f fe [2] 41 fe [2] 7e e2 }

  condition:
    any of them
}