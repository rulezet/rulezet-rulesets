rule TTP_XOR_WriteProcessMemory_2524 {
  strings:
    $key_2524 = { 72 56 [2] 40 74 [2] 46 41 [2] 68 41 [2] 57 5d }

  condition:
    any of them
}