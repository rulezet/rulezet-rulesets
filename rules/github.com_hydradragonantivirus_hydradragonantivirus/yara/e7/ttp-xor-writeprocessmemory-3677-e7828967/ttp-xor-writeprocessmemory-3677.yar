rule TTP_XOR_WriteProcessMemory_3677 {
  strings:
    $key_3677 = { 61 05 [2] 53 27 [2] 55 12 [2] 7b 12 [2] 44 0e }

  condition:
    any of them
}