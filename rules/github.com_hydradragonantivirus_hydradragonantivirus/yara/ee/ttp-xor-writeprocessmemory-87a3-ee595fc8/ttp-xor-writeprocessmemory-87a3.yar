rule TTP_XOR_WriteProcessMemory_87a3 {
  strings:
    $key_87a3 = { d0 d1 [2] e2 f3 [2] e4 c6 [2] ca c6 [2] f5 da }

  condition:
    any of them
}