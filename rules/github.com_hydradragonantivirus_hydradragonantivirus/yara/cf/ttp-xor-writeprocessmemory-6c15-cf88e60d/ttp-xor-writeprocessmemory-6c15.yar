rule TTP_XOR_WriteProcessMemory_6c15 {
  strings:
    $key_6c15 = { 3b 67 [2] 09 45 [2] 0f 70 [2] 21 70 [2] 1e 6c }

  condition:
    any of them
}