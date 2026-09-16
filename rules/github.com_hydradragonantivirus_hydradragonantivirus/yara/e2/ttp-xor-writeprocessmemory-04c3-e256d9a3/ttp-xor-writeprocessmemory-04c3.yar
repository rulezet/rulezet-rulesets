rule TTP_XOR_WriteProcessMemory_04c3 {
  strings:
    $key_04c3 = { 53 b1 [2] 61 93 [2] 67 a6 [2] 49 a6 [2] 76 ba }

  condition:
    any of them
}