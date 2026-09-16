rule TTP_XOR_WriteProcessMemory_0007 {
  strings:
    $key_0007 = { 57 75 [2] 65 57 [2] 63 62 [2] 4d 62 [2] 72 7e }

  condition:
    any of them
}