rule TTP_XOR_WriteProcessMemory_15ae {
  strings:
    $key_15ae = { 42 dc [2] 70 fe [2] 76 cb [2] 58 cb [2] 67 d7 }

  condition:
    any of them
}