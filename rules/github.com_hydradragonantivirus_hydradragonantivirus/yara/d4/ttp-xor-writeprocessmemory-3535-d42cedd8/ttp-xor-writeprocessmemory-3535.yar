rule TTP_XOR_WriteProcessMemory_3535 {
  strings:
    $key_3535 = { 62 47 [2] 50 65 [2] 56 50 [2] 78 50 [2] 47 4c }

  condition:
    any of them
}