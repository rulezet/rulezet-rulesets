rule TTP_XOR_WriteProcessMemory_00e6 {
  strings:
    $key_00e6 = { 57 94 [2] 65 b6 [2] 63 83 [2] 4d 83 [2] 72 9f }

  condition:
    any of them
}