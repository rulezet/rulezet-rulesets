rule TTP_XOR_WriteProcessMemory_87a5 {
  strings:
    $key_87a5 = { d0 d7 [2] e2 f5 [2] e4 c0 [2] ca c0 [2] f5 dc }

  condition:
    any of them
}