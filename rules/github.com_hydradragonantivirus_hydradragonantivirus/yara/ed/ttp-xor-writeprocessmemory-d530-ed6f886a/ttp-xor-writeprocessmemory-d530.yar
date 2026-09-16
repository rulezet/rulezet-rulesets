rule TTP_XOR_WriteProcessMemory_d530 {
  strings:
    $key_d530 = { 82 42 [2] b0 60 [2] b6 55 [2] 98 55 [2] a7 49 }

  condition:
    any of them
}