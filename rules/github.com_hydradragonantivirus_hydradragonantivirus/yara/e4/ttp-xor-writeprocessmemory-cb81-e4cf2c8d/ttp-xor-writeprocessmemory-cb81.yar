rule TTP_XOR_WriteProcessMemory_cb81 {
  strings:
    $key_cb81 = { 9c f3 [2] ae d1 [2] a8 e4 [2] 86 e4 [2] b9 f8 }

  condition:
    any of them
}