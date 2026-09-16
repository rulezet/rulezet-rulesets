rule TTP_XOR_WriteProcessMemory_2004 {
  strings:
    $key_2004 = { 77 76 [2] 45 54 [2] 43 61 [2] 6d 61 [2] 52 7d }

  condition:
    any of them
}