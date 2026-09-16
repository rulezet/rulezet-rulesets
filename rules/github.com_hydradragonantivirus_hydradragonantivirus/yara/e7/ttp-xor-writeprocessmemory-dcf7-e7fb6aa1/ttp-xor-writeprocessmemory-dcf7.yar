rule TTP_XOR_WriteProcessMemory_dcf7 {
  strings:
    $key_dcf7 = { 8b 85 [2] b9 a7 [2] bf 92 [2] 91 92 [2] ae 8e }

  condition:
    any of them
}