rule TTP_XOR_WriteProcessMemory_42c8 {
  strings:
    $key_42c8 = { 15 ba [2] 27 98 [2] 21 ad [2] 0f ad [2] 30 b1 }

  condition:
    any of them
}