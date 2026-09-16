rule TTP_XOR_WriteProcessMemory_90c1 {
  strings:
    $key_90c1 = { c7 b3 [2] f5 91 [2] f3 a4 [2] dd a4 [2] e2 b8 }

  condition:
    any of them
}