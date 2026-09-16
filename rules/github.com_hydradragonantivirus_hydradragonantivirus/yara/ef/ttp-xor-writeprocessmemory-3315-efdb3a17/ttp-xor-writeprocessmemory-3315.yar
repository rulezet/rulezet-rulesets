rule TTP_XOR_WriteProcessMemory_3315 {
  strings:
    $key_3315 = { 64 67 [2] 56 45 [2] 50 70 [2] 7e 70 [2] 41 6c }

  condition:
    any of them
}