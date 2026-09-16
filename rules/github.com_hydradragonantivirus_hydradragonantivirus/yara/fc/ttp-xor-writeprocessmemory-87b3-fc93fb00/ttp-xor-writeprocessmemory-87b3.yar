rule TTP_XOR_WriteProcessMemory_87b3 {
  strings:
    $key_87b3 = { d0 c1 [2] e2 e3 [2] e4 d6 [2] ca d6 [2] f5 ca }

  condition:
    any of them
}