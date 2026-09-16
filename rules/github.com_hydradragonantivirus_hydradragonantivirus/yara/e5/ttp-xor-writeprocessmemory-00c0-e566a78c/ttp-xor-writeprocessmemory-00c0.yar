rule TTP_XOR_WriteProcessMemory_00c0 {
  strings:
    $key_00c0 = { 57 b2 [2] 65 90 [2] 63 a5 [2] 4d a5 [2] 72 b9 }

  condition:
    any of them
}