rule TTP_XOR_WriteProcessMemory_0715 {
  strings:
    $key_0715 = { 50 67 [2] 62 45 [2] 64 70 [2] 4a 70 [2] 75 6c }

  condition:
    any of them
}