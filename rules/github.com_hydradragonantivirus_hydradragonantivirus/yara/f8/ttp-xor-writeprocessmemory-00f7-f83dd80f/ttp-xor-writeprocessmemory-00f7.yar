rule TTP_XOR_WriteProcessMemory_00f7 {
  strings:
    $key_00f7 = { 57 85 [2] 65 a7 [2] 63 92 [2] 4d 92 [2] 72 8e }

  condition:
    any of them
}