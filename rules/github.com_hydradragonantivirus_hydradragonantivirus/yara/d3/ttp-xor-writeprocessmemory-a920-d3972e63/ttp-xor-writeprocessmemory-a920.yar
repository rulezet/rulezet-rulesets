rule TTP_XOR_WriteProcessMemory_a920 {
  strings:
    $key_a920 = { fe 52 [2] cc 70 [2] ca 45 [2] e4 45 [2] db 59 }

  condition:
    any of them
}