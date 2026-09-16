rule TTP_XOR_WriteProcessMemory_07ae {
  strings:
    $key_07ae = { 50 dc [2] 62 fe [2] 64 cb [2] 4a cb [2] 75 d7 }

  condition:
    any of them
}