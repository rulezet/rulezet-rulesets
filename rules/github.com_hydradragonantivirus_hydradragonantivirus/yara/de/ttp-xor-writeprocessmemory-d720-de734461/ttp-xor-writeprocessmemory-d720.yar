rule TTP_XOR_WriteProcessMemory_d720 {
  strings:
    $key_d720 = { 80 52 [2] b2 70 [2] b4 45 [2] 9a 45 [2] a5 59 }

  condition:
    any of them
}