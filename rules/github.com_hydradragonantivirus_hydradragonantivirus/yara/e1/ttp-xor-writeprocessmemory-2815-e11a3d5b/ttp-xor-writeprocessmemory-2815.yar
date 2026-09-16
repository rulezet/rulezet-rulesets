rule TTP_XOR_WriteProcessMemory_2815 {
  strings:
    $key_2815 = { 7f 67 [2] 4d 45 [2] 4b 70 [2] 65 70 [2] 5a 6c }

  condition:
    any of them
}