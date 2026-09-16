rule TTP_XOR_WriteProcessMemory_71ae {
  strings:
    $key_71ae = { 26 dc [2] 14 fe [2] 12 cb [2] 3c cb [2] 03 d7 }

  condition:
    any of them
}