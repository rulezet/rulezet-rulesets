rule TTP_XOR_WriteProcessMemory_84ae {
  strings:
    $key_84ae = { d3 dc [2] e1 fe [2] e7 cb [2] c9 cb [2] f6 d7 }

  condition:
    any of them
}