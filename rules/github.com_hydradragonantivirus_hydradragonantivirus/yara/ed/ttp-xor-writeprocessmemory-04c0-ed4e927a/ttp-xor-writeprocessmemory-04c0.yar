rule TTP_XOR_WriteProcessMemory_04c0 {
  strings:
    $key_04c0 = { 53 b2 [2] 61 90 [2] 67 a5 [2] 49 a5 [2] 76 b9 }

  condition:
    any of them
}