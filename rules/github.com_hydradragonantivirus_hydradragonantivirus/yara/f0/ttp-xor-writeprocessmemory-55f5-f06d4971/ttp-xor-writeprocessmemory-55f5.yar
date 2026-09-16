rule TTP_XOR_WriteProcessMemory_55f5 {
  strings:
    $key_55f5 = { 02 87 [2] 30 a5 [2] 36 90 [2] 18 90 [2] 27 8c }

  condition:
    any of them
}