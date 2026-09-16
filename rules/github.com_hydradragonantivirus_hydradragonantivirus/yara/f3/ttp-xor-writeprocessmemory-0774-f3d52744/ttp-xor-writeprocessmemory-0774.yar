rule TTP_XOR_WriteProcessMemory_0774 {
  strings:
    $key_0774 = { 50 06 [2] 62 24 [2] 64 11 [2] 4a 11 [2] 75 0d }

  condition:
    any of them
}