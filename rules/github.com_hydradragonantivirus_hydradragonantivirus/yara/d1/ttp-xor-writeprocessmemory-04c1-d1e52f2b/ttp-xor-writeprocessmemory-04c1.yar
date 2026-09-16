rule TTP_XOR_WriteProcessMemory_04c1 {
  strings:
    $key_04c1 = { 53 b3 [2] 61 91 [2] 67 a4 [2] 49 a4 [2] 76 b8 }

  condition:
    any of them
}