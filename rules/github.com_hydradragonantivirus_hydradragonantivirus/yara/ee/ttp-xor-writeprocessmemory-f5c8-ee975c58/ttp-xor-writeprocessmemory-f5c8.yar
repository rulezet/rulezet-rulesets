rule TTP_XOR_WriteProcessMemory_f5c8 {
  strings:
    $key_f5c8 = { a2 ba [2] 90 98 [2] 96 ad [2] b8 ad [2] 87 b1 }

  condition:
    any of them
}