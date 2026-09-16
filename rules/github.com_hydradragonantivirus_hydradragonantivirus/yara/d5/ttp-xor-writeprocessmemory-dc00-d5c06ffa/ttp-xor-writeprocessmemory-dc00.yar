rule TTP_XOR_WriteProcessMemory_dc00 {
  strings:
    $key_dc00 = { 8b 72 [2] b9 50 [2] bf 65 [2] 91 65 [2] ae 79 }

  condition:
    any of them
}