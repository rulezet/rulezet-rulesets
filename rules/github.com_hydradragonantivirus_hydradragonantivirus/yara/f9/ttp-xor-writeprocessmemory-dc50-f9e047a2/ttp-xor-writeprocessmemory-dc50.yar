rule TTP_XOR_WriteProcessMemory_dc50 {
  strings:
    $key_dc50 = { 8b 22 [2] b9 00 [2] bf 35 [2] 91 35 [2] ae 29 }

  condition:
    any of them
}