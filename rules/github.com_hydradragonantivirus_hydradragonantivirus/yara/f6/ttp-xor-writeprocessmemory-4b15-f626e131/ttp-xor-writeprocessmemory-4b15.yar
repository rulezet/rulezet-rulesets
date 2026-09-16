rule TTP_XOR_WriteProcessMemory_4b15 {
  strings:
    $key_4b15 = { 1c 67 [2] 2e 45 [2] 28 70 [2] 06 70 [2] 39 6c }

  condition:
    any of them
}