rule TTP_XOR_WriteProcessMemory_5202 {
  strings:
    $key_5202 = { 05 70 [2] 37 52 [2] 31 67 [2] 1f 67 [2] 20 7b }

  condition:
    any of them
}