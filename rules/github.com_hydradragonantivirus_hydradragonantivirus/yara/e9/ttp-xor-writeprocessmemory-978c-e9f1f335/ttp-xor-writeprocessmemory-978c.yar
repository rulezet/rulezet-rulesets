rule TTP_XOR_WriteProcessMemory_978c {
  strings:
    $key_978c = { c0 fe [2] f2 dc [2] f4 e9 [2] da e9 [2] e5 f5 }

  condition:
    any of them
}