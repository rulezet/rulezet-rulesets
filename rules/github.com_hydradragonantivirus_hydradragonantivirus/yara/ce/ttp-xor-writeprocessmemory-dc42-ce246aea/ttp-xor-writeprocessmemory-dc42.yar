rule TTP_XOR_WriteProcessMemory_dc42 {
  strings:
    $key_dc42 = { 8b 30 [2] b9 12 [2] bf 27 [2] 91 27 [2] ae 3b }

  condition:
    any of them
}