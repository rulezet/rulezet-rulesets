rule TTP_XOR_WriteProcessMemory_0011 {
  strings:
    $key_0011 = { 57 63 [2] 65 41 [2] 63 74 [2] 4d 74 [2] 72 68 }

  condition:
    any of them
}