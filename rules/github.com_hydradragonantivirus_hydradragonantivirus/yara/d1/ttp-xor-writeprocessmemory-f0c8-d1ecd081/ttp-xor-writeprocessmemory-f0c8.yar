rule TTP_XOR_WriteProcessMemory_f0c8 {
  strings:
    $key_f0c8 = { a7 ba [2] 95 98 [2] 93 ad [2] bd ad [2] 82 b1 }

  condition:
    any of them
}