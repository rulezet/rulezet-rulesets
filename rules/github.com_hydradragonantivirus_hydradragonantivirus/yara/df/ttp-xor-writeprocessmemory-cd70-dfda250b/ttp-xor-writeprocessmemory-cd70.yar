rule TTP_XOR_WriteProcessMemory_cd70 {
  strings:
    $key_cd70 = { 9a 02 [2] a8 20 [2] ae 15 [2] 80 15 [2] bf 09 }

  condition:
    any of them
}