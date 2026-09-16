rule TTP_XOR_WriteProcessMemory_cdb9 {
  strings:
    $key_cdb9 = { 9a cb [2] a8 e9 [2] ae dc [2] 80 dc [2] bf c0 }

  condition:
    any of them
}