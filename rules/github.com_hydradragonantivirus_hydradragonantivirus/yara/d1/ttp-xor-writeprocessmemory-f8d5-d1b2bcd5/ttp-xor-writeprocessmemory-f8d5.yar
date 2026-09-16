rule TTP_XOR_WriteProcessMemory_f8d5 {
  strings:
    $key_f8d5 = { af a7 [2] 9d 85 [2] 9b b0 [2] b5 b0 [2] 8a ac }

  condition:
    any of them
}