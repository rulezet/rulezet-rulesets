rule TTP_XOR_WriteProcessMemory_cde1 {
  strings:
    $key_cde1 = { 9a 93 [2] a8 b1 [2] ae 84 [2] 80 84 [2] bf 98 }

  condition:
    any of them
}