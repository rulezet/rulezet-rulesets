rule TTP_XOR_WriteProcessMemory_d230 {
  strings:
    $key_d230 = { 85 42 [2] b7 60 [2] b1 55 [2] 9f 55 [2] a0 49 }

  condition:
    any of them
}