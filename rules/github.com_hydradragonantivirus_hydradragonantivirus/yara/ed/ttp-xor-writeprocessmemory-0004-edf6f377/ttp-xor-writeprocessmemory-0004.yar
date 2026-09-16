rule TTP_XOR_WriteProcessMemory_0004 {
  strings:
    $key_0004 = { 57 76 [2] 65 54 [2] 63 61 [2] 4d 61 [2] 72 7d }

  condition:
    any of them
}