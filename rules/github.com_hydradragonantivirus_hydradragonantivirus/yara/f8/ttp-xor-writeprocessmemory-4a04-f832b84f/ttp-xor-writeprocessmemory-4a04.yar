rule TTP_XOR_WriteProcessMemory_4a04 {
  strings:
    $key_4a04 = { 1d 76 [2] 2f 54 [2] 29 61 [2] 07 61 [2] 38 7d }

  condition:
    any of them
}