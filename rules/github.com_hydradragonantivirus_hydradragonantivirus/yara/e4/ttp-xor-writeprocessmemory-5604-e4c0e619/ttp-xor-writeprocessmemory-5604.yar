rule TTP_XOR_WriteProcessMemory_5604 {
  strings:
    $key_5604 = { 01 76 [2] 33 54 [2] 35 61 [2] 1b 61 [2] 24 7d }

  condition:
    any of them
}