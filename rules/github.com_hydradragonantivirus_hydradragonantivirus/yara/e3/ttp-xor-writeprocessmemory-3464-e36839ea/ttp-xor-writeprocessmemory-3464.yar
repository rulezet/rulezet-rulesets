rule TTP_XOR_WriteProcessMemory_3464 {
  strings:
    $key_3464 = { 63 16 [2] 51 34 [2] 57 01 [2] 79 01 [2] 46 1d }

  condition:
    any of them
}