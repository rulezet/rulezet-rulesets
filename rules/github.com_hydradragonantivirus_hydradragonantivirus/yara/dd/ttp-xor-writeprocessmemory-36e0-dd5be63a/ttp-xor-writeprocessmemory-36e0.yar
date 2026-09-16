rule TTP_XOR_WriteProcessMemory_36e0 {
  strings:
    $key_36e0 = { 61 92 [2] 53 b0 [2] 55 85 [2] 7b 85 [2] 44 99 }

  condition:
    any of them
}