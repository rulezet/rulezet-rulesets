rule TTP_XOR_WriteProcessMemory_00d0 {
  strings:
    $key_00d0 = { 57 a2 [2] 65 80 [2] 63 b5 [2] 4d b5 [2] 72 a9 }

  condition:
    any of them
}