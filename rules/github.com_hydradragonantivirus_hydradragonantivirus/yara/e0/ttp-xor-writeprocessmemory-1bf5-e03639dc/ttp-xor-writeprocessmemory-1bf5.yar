rule TTP_XOR_WriteProcessMemory_1bf5 {
  strings:
    $key_1bf5 = { 4c 87 [2] 7e a5 [2] 78 90 [2] 56 90 [2] 69 8c }

  condition:
    any of them
}