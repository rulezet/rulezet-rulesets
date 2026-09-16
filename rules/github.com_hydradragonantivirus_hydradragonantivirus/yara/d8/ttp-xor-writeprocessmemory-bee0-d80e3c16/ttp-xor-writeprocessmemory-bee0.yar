rule TTP_XOR_WriteProcessMemory_bee0 {
  strings:
    $key_bee0 = { e9 92 [2] db b0 [2] dd 85 [2] f3 85 [2] cc 99 }

  condition:
    any of them
}