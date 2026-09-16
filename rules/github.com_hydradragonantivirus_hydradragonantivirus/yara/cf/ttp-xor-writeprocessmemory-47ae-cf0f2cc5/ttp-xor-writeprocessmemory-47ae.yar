rule TTP_XOR_WriteProcessMemory_47ae {
  strings:
    $key_47ae = { 10 dc [2] 22 fe [2] 24 cb [2] 0a cb [2] 35 d7 }

  condition:
    any of them
}