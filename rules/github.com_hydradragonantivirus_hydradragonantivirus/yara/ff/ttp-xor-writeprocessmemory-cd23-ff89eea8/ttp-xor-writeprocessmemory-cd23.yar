rule TTP_XOR_WriteProcessMemory_cd23 {
  strings:
    $key_cd23 = { 9a 51 [2] a8 73 [2] ae 46 [2] 80 46 [2] bf 5a }

  condition:
    any of them
}