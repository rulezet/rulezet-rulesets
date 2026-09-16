rule TTP_XOR_WriteProcessMemory_5315 {
  strings:
    $key_5315 = { 04 67 [2] 36 45 [2] 30 70 [2] 1e 70 [2] 21 6c }

  condition:
    any of them
}