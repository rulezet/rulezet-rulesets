rule TTP_XOR_WriteProcessMemory_d520 {
  strings:
    $key_d520 = { 82 52 [2] b0 70 [2] b6 45 [2] 98 45 [2] a7 59 }

  condition:
    any of them
}