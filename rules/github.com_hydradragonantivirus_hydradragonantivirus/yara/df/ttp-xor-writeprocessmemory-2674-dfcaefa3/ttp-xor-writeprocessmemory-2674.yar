rule TTP_XOR_WriteProcessMemory_2674 {
  strings:
    $key_2674 = { 71 06 [2] 43 24 [2] 45 11 [2] 6b 11 [2] 54 0d }

  condition:
    any of them
}