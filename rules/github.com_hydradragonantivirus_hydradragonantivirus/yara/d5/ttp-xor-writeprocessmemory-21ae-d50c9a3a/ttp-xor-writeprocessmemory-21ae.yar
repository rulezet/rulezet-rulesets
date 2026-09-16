rule TTP_XOR_WriteProcessMemory_21ae {
  strings:
    $key_21ae = { 76 dc [2] 44 fe [2] 42 cb [2] 6c cb [2] 53 d7 }

  condition:
    any of them
}