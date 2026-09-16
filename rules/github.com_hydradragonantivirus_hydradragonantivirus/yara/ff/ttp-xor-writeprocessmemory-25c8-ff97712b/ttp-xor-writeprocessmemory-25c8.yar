rule TTP_XOR_WriteProcessMemory_25c8 {
  strings:
    $key_25c8 = { 72 ba [2] 40 98 [2] 46 ad [2] 68 ad [2] 57 b1 }

  condition:
    any of them
}