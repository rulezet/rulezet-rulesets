rule TTP_XOR_WriteProcessMemory_90c3 {
  strings:
    $key_90c3 = { c7 b1 [2] f5 93 [2] f3 a6 [2] dd a6 [2] e2 ba }

  condition:
    any of them
}