rule TTP_XOR_WriteProcessMemory_5124 {
  strings:
    $key_5124 = { 06 56 [2] 34 74 [2] 32 41 [2] 1c 41 [2] 23 5d }

  condition:
    any of them
}