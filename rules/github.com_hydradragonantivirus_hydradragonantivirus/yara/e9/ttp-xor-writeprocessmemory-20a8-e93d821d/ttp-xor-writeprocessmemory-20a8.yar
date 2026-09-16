rule TTP_XOR_WriteProcessMemory_20a8 {
  strings:
    $key_20a8 = { 77 da [2] 45 f8 [2] 43 cd [2] 6d cd [2] 52 d1 }

  condition:
    any of them
}