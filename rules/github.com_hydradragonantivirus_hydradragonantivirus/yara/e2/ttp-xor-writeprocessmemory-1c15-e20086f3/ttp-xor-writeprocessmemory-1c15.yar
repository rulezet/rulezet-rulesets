rule TTP_XOR_WriteProcessMemory_1c15 {
  strings:
    $key_1c15 = { 4b 67 [2] 79 45 [2] 7f 70 [2] 51 70 [2] 6e 6c }

  condition:
    any of them
}