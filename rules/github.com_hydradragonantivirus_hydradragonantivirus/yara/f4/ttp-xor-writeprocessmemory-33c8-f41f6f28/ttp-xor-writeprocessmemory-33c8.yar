rule TTP_XOR_WriteProcessMemory_33c8 {
  strings:
    $key_33c8 = { 64 ba [2] 56 98 [2] 50 ad [2] 7e ad [2] 41 b1 }

  condition:
    any of them
}