rule TTP_XOR_WriteProcessMemory_1361 {
  strings:
    $key_1361 = { 44 13 [2] 76 31 [2] 70 04 [2] 5e 04 [2] 61 18 }

  condition:
    any of them
}