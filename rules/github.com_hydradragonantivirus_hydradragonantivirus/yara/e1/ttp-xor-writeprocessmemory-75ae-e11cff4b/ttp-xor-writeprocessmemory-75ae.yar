rule TTP_XOR_WriteProcessMemory_75ae {
  strings:
    $key_75ae = { 22 dc [2] 10 fe [2] 16 cb [2] 38 cb [2] 07 d7 }

  condition:
    any of them
}