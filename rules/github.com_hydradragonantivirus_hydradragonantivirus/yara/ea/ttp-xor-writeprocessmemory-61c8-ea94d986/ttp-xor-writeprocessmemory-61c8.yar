rule TTP_XOR_WriteProcessMemory_61c8 {
  strings:
    $key_61c8 = { 36 ba [2] 04 98 [2] 02 ad [2] 2c ad [2] 13 b1 }

  condition:
    any of them
}