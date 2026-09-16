rule TTP_XOR_WriteProcessMemory_5024 {
  strings:
    $key_5024 = { 07 56 [2] 35 74 [2] 33 41 [2] 1d 41 [2] 22 5d }

  condition:
    any of them
}