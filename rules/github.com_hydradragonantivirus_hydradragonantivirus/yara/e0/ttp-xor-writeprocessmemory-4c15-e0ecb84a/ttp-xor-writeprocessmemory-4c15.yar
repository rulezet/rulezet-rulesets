rule TTP_XOR_WriteProcessMemory_4c15 {
  strings:
    $key_4c15 = { 1b 67 [2] 29 45 [2] 2f 70 [2] 01 70 [2] 3e 6c }

  condition:
    any of them
}