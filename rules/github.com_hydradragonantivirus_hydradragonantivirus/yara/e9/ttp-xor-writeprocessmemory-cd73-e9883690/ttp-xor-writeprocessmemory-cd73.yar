rule TTP_XOR_WriteProcessMemory_cd73 {
  strings:
    $key_cd73 = { 9a 01 [2] a8 23 [2] ae 16 [2] 80 16 [2] bf 0a }

  condition:
    any of them
}