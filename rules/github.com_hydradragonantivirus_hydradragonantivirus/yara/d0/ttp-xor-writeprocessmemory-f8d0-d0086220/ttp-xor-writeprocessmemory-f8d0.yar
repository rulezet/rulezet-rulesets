rule TTP_XOR_WriteProcessMemory_f8d0 {
  strings:
    $key_f8d0 = { af a2 [2] 9d 80 [2] 9b b5 [2] b5 b5 [2] 8a a9 }

  condition:
    any of them
}