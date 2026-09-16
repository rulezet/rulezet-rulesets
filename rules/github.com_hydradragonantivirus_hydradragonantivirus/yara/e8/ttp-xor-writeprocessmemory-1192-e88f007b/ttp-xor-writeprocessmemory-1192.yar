rule TTP_XOR_WriteProcessMemory_1192 {
  strings:
    $key_1192 = { 46 e0 [2] 74 c2 [2] 72 f7 [2] 5c f7 [2] 63 eb }

  condition:
    any of them
}