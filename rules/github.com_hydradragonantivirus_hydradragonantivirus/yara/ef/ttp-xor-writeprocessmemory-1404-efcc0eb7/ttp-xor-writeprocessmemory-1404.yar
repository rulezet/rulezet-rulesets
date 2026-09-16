rule TTP_XOR_WriteProcessMemory_1404 {
  strings:
    $key_1404 = { 43 76 [2] 71 54 [2] 77 61 [2] 59 61 [2] 66 7d }

  condition:
    any of them
}