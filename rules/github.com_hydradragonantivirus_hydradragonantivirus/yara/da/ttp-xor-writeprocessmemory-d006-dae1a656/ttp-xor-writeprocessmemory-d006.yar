rule TTP_XOR_WriteProcessMemory_d006 {
  strings:
    $key_d006 = { 87 74 [2] b5 56 [2] b3 63 [2] 9d 63 [2] a2 7f }

  condition:
    any of them
}