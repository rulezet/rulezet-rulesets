rule TTP_XOR_WriteProcessMemory_00d6 {
  strings:
    $key_00d6 = { 57 a4 [2] 65 86 [2] 63 b3 [2] 4d b3 [2] 72 af }

  condition:
    any of them
}