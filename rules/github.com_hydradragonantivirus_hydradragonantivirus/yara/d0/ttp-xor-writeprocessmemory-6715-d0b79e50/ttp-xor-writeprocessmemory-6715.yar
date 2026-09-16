rule TTP_XOR_WriteProcessMemory_6715 {
  strings:
    $key_6715 = { 30 67 [2] 02 45 [2] 04 70 [2] 2a 70 [2] 15 6c }

  condition:
    any of them
}