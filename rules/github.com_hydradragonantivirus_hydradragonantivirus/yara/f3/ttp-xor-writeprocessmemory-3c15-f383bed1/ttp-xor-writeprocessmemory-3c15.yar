rule TTP_XOR_WriteProcessMemory_3c15 {
  strings:
    $key_3c15 = { 6b 67 [2] 59 45 [2] 5f 70 [2] 71 70 [2] 4e 6c }

  condition:
    any of them
}