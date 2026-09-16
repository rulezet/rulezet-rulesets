rule TTP_XOR_WriteProcessMemory_0060 {
  strings:
    $key_0060 = { 57 12 [2] 65 30 [2] 63 05 [2] 4d 05 [2] 72 19 }

  condition:
    any of them
}