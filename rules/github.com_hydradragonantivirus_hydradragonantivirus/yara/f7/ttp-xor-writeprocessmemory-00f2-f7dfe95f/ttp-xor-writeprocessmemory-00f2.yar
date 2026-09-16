rule TTP_XOR_WriteProcessMemory_00f2 {
  strings:
    $key_00f2 = { 57 80 [2] 65 a2 [2] 63 97 [2] 4d 97 [2] 72 8b }

  condition:
    any of them
}