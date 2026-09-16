rule TTP_XOR_WriteProcessMemory_d4c8 {
  strings:
    $key_d4c8 = { 83 ba [2] b1 98 [2] b7 ad [2] 99 ad [2] a6 b1 }

  condition:
    any of them
}