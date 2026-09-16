rule TTP_XOR_WriteProcessMemory_0003 {
  strings:
    $key_0003 = { 57 71 [2] 65 53 [2] 63 66 [2] 4d 66 [2] 72 7a }

  condition:
    any of them
}