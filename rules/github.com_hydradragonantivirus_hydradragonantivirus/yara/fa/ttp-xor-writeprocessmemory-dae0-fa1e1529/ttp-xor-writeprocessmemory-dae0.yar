rule TTP_XOR_WriteProcessMemory_dae0 {
  strings:
    $key_dae0 = { 8d 92 [2] bf b0 [2] b9 85 [2] 97 85 [2] a8 99 }

  condition:
    any of them
}