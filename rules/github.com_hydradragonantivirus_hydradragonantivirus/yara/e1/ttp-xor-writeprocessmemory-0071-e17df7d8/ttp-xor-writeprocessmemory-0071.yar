rule TTP_XOR_WriteProcessMemory_0071 {
  strings:
    $key_0071 = { 57 03 [2] 65 21 [2] 63 14 [2] 4d 14 [2] 72 08 }

  condition:
    any of them
}