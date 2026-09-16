rule TTP_XOR_WriteProcessMemory_d570 {
  strings:
    $key_d570 = { 82 02 [2] b0 20 [2] b6 15 [2] 98 15 [2] a7 09 }

  condition:
    any of them
}