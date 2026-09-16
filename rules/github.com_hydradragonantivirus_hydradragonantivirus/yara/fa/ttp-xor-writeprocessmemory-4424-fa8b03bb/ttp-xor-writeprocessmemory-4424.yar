rule TTP_XOR_WriteProcessMemory_4424 {
  strings:
    $key_4424 = { 13 56 [2] 21 74 [2] 27 41 [2] 09 41 [2] 36 5d }

  condition:
    any of them
}