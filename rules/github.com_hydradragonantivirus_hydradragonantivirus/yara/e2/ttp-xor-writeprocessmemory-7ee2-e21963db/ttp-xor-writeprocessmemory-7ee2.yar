rule TTP_XOR_WriteProcessMemory_7ee2 {
  strings:
    $key_7ee2 = { 29 90 [2] 1b b2 [2] 1d 87 [2] 33 87 [2] 0c 9b }

  condition:
    any of them
}