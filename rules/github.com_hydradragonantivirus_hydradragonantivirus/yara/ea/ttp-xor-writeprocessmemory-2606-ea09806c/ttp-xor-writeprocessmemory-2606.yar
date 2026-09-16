rule TTP_XOR_WriteProcessMemory_2606 {
  strings:
    $key_2606 = { 71 74 [2] 43 56 [2] 45 63 [2] 6b 63 [2] 54 7f }

  condition:
    any of them
}