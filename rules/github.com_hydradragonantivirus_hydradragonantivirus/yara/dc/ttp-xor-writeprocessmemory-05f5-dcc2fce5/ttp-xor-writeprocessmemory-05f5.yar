rule TTP_XOR_WriteProcessMemory_05f5 {
  strings:
    $key_05f5 = { 52 87 [2] 60 a5 [2] 66 90 [2] 48 90 [2] 77 8c }

  condition:
    any of them
}