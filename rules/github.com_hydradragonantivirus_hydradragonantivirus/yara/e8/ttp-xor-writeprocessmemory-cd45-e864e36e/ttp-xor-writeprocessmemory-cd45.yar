rule TTP_XOR_WriteProcessMemory_cd45 {
  strings:
    $key_cd45 = { 9a 37 [2] a8 15 [2] ae 20 [2] 80 20 [2] bf 3c }

  condition:
    any of them
}