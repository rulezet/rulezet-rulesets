rule TTP_XOR_WriteProcessMemory_bed2 {
  strings:
    $key_bed2 = { e9 a0 [2] db 82 [2] dd b7 [2] f3 b7 [2] cc ab }

  condition:
    any of them
}