rule TTP_XOR_WriteProcessMemory_bed7 {
  strings:
    $key_bed7 = { e9 a5 [2] db 87 [2] dd b2 [2] f3 b2 [2] cc ae }

  condition:
    any of them
}