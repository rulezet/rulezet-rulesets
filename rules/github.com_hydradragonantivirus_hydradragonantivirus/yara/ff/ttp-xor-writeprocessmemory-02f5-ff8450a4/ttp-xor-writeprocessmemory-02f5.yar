rule TTP_XOR_WriteProcessMemory_02f5 {
  strings:
    $key_02f5 = { 55 87 [2] 67 a5 [2] 61 90 [2] 4f 90 [2] 70 8c }

  condition:
    any of them
}