rule TTP_XOR_WriteProcessMemory_a5ae {
  strings:
    $key_a5ae = { f2 dc [2] c0 fe [2] c6 cb [2] e8 cb [2] d7 d7 }

  condition:
    any of them
}