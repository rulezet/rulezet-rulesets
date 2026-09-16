rule TTP_XOR_WriteProcessMemory_1211 {
  strings:
    $key_1211 = { 45 63 [2] 77 41 [2] 71 74 [2] 5f 74 [2] 60 68 }

  condition:
    any of them
}