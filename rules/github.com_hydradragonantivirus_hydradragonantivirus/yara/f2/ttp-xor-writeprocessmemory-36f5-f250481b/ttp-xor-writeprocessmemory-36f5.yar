rule TTP_XOR_WriteProcessMemory_36f5 {
  strings:
    $key_36f5 = { 61 87 [2] 53 a5 [2] 55 90 [2] 7b 90 [2] 44 8c }

  condition:
    any of them
}