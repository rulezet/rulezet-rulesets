rule TTP_XOR_WriteProcessMemory_2060 {
  strings:
    $key_2060 = { 77 12 [2] 45 30 [2] 43 05 [2] 6d 05 [2] 52 19 }

  condition:
    any of them
}