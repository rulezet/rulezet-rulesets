rule TTP_XOR_WriteProcessMemory_1194 {
  strings:
    $key_1194 = { 46 e6 [2] 74 c4 [2] 72 f1 [2] 5c f1 [2] 63 ed }

  condition:
    any of them
}