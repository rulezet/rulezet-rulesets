rule TTP_XOR_WriteProcessMemory_dc73 {
  strings:
    $key_dc73 = { 8b 01 [2] b9 23 [2] bf 16 [2] 91 16 [2] ae 0a }

  condition:
    any of them
}