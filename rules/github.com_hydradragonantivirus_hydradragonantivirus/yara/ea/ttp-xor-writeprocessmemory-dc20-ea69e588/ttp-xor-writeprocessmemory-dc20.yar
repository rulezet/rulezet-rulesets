rule TTP_XOR_WriteProcessMemory_dc20 {
  strings:
    $key_dc20 = { 8b 52 [2] b9 70 [2] bf 45 [2] 91 45 [2] ae 59 }

  condition:
    any of them
}