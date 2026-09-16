rule TTP_XOR_WriteProcessMemory_f0a8 {
  strings:
    $key_f0a8 = { a7 da [2] 95 f8 [2] 93 cd [2] bd cd [2] 82 d1 }

  condition:
    any of them
}