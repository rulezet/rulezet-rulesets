rule TTP_XOR_WriteProcessMemory_4015 {
  strings:
    $key_4015 = { 17 67 [2] 25 45 [2] 23 70 [2] 0d 70 [2] 32 6c }

  condition:
    any of them
}