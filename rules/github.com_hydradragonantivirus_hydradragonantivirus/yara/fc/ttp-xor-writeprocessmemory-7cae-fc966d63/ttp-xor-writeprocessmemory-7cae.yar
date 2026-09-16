rule TTP_XOR_WriteProcessMemory_7cae {
  strings:
    $key_7cae = { 2b dc [2] 19 fe [2] 1f cb [2] 31 cb [2] 0e d7 }

  condition:
    any of them
}