rule TTP_XOR_WriteProcessMemory_0bf5 {
  strings:
    $key_0bf5 = { 5c 87 [2] 6e a5 [2] 68 90 [2] 46 90 [2] 79 8c }

  condition:
    any of them
}