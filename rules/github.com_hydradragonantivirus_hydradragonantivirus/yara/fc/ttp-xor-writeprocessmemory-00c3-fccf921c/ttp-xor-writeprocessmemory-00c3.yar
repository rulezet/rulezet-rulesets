rule TTP_XOR_WriteProcessMemory_00c3 {
  strings:
    $key_00c3 = { 57 b1 [2] 65 93 [2] 63 a6 [2] 4d a6 [2] 72 ba }

  condition:
    any of them
}