rule TTP_XOR_WriteProcessMemory_64ae {
  strings:
    $key_64ae = { 33 dc [2] 01 fe [2] 07 cb [2] 29 cb [2] 16 d7 }

  condition:
    any of them
}