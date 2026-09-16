rule TTP_XOR_WriteProcessMemory_cd95 {
  strings:
    $key_cd95 = { 9a e7 [2] a8 c5 [2] ae f0 [2] 80 f0 [2] bf ec }

  condition:
    any of them
}