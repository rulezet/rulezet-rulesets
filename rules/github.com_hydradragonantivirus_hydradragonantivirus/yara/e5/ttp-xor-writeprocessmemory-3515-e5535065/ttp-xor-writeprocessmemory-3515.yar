rule TTP_XOR_WriteProcessMemory_3515 {
  strings:
    $key_3515 = { 62 67 [2] 50 45 [2] 56 70 [2] 78 70 [2] 47 6c }

  condition:
    any of them
}