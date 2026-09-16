rule TTP_XOR_WriteProcessMemory_5380 {
  strings:
    $key_5380 = { 04 f2 [2] 36 d0 [2] 30 e5 [2] 1e e5 [2] 21 f9 }

  condition:
    any of them
}