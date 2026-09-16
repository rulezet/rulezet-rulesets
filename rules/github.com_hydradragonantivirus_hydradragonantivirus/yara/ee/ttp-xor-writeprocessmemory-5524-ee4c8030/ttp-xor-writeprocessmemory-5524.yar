rule TTP_XOR_WriteProcessMemory_5524 {
  strings:
    $key_5524 = { 02 56 [2] 30 74 [2] 36 41 [2] 18 41 [2] 27 5d }

  condition:
    any of them
}