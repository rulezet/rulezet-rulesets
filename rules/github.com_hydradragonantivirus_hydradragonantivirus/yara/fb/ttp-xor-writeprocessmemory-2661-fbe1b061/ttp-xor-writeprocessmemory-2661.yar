rule TTP_XOR_WriteProcessMemory_2661 {
  strings:
    $key_2661 = { 71 13 [2] 43 31 [2] 45 04 [2] 6b 04 [2] 54 18 }

  condition:
    any of them
}