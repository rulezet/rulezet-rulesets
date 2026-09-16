rule TTP_XOR_WriteProcessMemory_3215 {
  strings:
    $key_3215 = { 65 67 [2] 57 45 [2] 51 70 [2] 7f 70 [2] 40 6c }

  condition:
    any of them
}