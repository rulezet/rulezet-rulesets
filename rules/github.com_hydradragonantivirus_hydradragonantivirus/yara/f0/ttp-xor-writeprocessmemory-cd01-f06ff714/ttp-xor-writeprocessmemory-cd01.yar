rule TTP_XOR_WriteProcessMemory_cd01 {
  strings:
    $key_cd01 = { 9a 73 [2] a8 51 [2] ae 64 [2] 80 64 [2] bf 78 }

  condition:
    any of them
}