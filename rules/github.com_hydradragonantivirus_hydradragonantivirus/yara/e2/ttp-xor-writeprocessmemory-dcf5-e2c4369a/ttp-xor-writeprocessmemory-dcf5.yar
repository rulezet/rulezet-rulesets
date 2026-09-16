rule TTP_XOR_WriteProcessMemory_dcf5 {
  strings:
    $key_dcf5 = { 8b 87 [2] b9 a5 [2] bf 90 [2] 91 90 [2] ae 8c }

  condition:
    any of them
}