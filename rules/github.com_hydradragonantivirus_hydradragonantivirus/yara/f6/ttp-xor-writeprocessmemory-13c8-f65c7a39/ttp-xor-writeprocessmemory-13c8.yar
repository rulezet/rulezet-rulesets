rule TTP_XOR_WriteProcessMemory_13c8 {
  strings:
    $key_13c8 = { 44 ba [2] 76 98 [2] 70 ad [2] 5e ad [2] 61 b1 }

  condition:
    any of them
}