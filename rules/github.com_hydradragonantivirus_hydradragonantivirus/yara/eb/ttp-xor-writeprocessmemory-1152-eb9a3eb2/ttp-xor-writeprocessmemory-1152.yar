rule TTP_XOR_WriteProcessMemory_1152 {
  strings:
    $key_1152 = { 46 20 [2] 74 02 [2] 72 37 [2] 5c 37 [2] 63 2b }

  condition:
    any of them
}