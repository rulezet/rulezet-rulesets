rule TTP_XOR_WriteProcessMemory_dc81 {
  strings:
    $key_dc81 = { 8b f3 [2] b9 d1 [2] bf e4 [2] 91 e4 [2] ae f8 }

  condition:
    any of them
}