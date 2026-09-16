rule TTP_XOR_WriteProcessMemory_4bf5 {
  strings:
    $key_4bf5 = { 1c 87 [2] 2e a5 [2] 28 90 [2] 06 90 [2] 39 8c }

  condition:
    any of them
}