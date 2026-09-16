rule TTP_XOR_WriteProcessMemory_7677 {
  strings:
    $key_7677 = { 21 05 [2] 13 27 [2] 15 12 [2] 3b 12 [2] 04 0e }

  condition:
    any of them
}