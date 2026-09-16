rule TTP_XOR_WriteProcessMemory_dc74 {
  strings:
    $key_dc74 = { 8b 06 [2] b9 24 [2] bf 11 [2] 91 11 [2] ae 0d }

  condition:
    any of them
}