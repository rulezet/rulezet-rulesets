rule TTP_XOR_WriteProcessMemory_2c9b {
  strings:
    $key_2c9b = { 7b e9 [2] 49 cb [2] 4f fe [2] 61 fe [2] 5e e2 }

  condition:
    any of them
}