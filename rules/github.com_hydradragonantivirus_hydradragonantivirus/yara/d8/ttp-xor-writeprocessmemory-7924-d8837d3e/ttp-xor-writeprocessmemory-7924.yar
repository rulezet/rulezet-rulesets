rule TTP_XOR_WriteProcessMemory_7924 {
  strings:
    $key_7924 = { 2e 56 [2] 1c 74 [2] 1a 41 [2] 34 41 [2] 0b 5d }

  condition:
    any of them
}