rule TTP_XOR_WriteProcessMemory_cd74 {
  strings:
    $key_cd74 = { 9a 06 [2] a8 24 [2] ae 11 [2] 80 11 [2] bf 0d }

  condition:
    any of them
}