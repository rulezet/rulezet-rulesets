rule TTP_XOR_WriteProcessMemory_26ae {
  strings:
    $key_26ae = { 71 dc [2] 43 fe [2] 45 cb [2] 6b cb [2] 54 d7 }

  condition:
    any of them
}