rule TTP_XOR_WriteProcessMemory_dc15 {
  strings:
    $key_dc15 = { 8b 67 [2] b9 45 [2] bf 70 [2] 91 70 [2] ae 6c }

  condition:
    any of them
}