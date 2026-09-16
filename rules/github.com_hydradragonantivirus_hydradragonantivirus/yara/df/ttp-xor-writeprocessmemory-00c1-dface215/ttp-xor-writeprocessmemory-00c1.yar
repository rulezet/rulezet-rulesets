rule TTP_XOR_WriteProcessMemory_00c1 {
  strings:
    $key_00c1 = { 57 b3 [2] 65 91 [2] 63 a4 [2] 4d a4 [2] 72 b8 }

  condition:
    any of them
}