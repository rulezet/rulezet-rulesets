rule TTP_XOR_WriteProcessMemory_53c8 {
  strings:
    $key_53c8 = { 04 ba [2] 36 98 [2] 30 ad [2] 1e ad [2] 21 b1 }

  condition:
    any of them
}