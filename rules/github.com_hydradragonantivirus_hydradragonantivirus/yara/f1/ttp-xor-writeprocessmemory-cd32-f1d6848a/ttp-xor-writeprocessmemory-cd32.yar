rule TTP_XOR_WriteProcessMemory_cd32 {
  strings:
    $key_cd32 = { 9a 40 [2] a8 62 [2] ae 57 [2] 80 57 [2] bf 4b }

  condition:
    any of them
}