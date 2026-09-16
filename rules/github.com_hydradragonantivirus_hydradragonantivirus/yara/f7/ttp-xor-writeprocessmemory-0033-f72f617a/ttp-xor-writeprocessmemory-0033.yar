rule TTP_XOR_WriteProcessMemory_0033 {
  strings:
    $key_0033 = { 57 41 [2] 65 63 [2] 63 56 [2] 4d 56 [2] 72 4a }

  condition:
    any of them
}