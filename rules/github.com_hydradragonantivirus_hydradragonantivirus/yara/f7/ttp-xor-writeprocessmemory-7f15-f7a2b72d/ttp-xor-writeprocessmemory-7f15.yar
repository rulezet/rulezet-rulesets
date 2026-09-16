rule TTP_XOR_WriteProcessMemory_7f15 {
  strings:
    $key_7f15 = { 28 67 [2] 1a 45 [2] 1c 70 [2] 32 70 [2] 0d 6c }

  condition:
    any of them
}