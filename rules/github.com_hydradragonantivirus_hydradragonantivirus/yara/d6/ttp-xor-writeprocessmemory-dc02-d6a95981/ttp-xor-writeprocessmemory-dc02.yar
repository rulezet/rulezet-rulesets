rule TTP_XOR_WriteProcessMemory_dc02 {
  strings:
    $key_dc02 = { 8b 70 [2] b9 52 [2] bf 67 [2] 91 67 [2] ae 7b }

  condition:
    any of them
}