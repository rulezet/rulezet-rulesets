rule TTP_XOR_WriteProcessMemory_1674 {
  strings:
    $key_1674 = { 41 06 [2] 73 24 [2] 75 11 [2] 5b 11 [2] 64 0d }

  condition:
    any of them
}