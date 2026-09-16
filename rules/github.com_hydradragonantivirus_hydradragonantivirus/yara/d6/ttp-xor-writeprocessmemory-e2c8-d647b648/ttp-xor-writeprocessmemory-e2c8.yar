rule TTP_XOR_WriteProcessMemory_e2c8 {
  strings:
    $key_e2c8 = { b5 ba [2] 87 98 [2] 81 ad [2] af ad [2] 90 b1 }

  condition:
    any of them
}