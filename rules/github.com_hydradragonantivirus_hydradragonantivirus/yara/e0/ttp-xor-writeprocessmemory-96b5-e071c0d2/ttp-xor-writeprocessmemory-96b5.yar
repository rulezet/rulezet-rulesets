rule TTP_XOR_WriteProcessMemory_96b5 {
  strings:
    $key_96b5 = { c1 c7 [2] f3 e5 [2] f5 d0 [2] db d0 [2] e4 cc }

  condition:
    any of them
}