rule TTP_XOR_WriteProcessMemory_40c8 {
  strings:
    $key_40c8 = { 17 ba [2] 25 98 [2] 23 ad [2] 0d ad [2] 32 b1 }

  condition:
    any of them
}