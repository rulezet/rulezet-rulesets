rule TTP_XOR_WriteProcessMemory_dcd9 {
  strings:
    $key_dcd9 = { 8b ab [2] b9 89 [2] bf bc [2] 91 bc [2] ae a0 }

  condition:
    any of them
}