rule TTP_XOR_WriteProcessMemory_0261 {
  strings:
    $key_0261 = { 55 13 [2] 67 31 [2] 61 04 [2] 4f 04 [2] 70 18 }

  condition:
    any of them
}