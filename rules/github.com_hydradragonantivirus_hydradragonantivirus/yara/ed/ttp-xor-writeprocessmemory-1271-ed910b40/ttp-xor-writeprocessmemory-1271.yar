rule TTP_XOR_WriteProcessMemory_1271 {
  strings:
    $key_1271 = { 45 03 [2] 77 21 [2] 71 14 [2] 5f 14 [2] 60 08 }

  condition:
    any of them
}