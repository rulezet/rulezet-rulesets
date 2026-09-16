rule TTP_XOR_WriteProcessMemory_7621 {
  strings:
    $key_7621 = { 21 53 [2] 13 71 [2] 15 44 [2] 3b 44 [2] 04 58 }

  condition:
    any of them
}