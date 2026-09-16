rule TTP_XOR_WriteProcessMemory_72c8 {
  strings:
    $key_72c8 = { 25 ba [2] 17 98 [2] 11 ad [2] 3f ad [2] 00 b1 }

  condition:
    any of them
}