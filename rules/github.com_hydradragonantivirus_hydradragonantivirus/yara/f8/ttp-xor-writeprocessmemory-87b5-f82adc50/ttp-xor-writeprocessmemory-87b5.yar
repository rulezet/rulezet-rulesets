rule TTP_XOR_WriteProcessMemory_87b5 {
  strings:
    $key_87b5 = { d0 c7 [2] e2 e5 [2] e4 d0 [2] ca d0 [2] f5 cc }

  condition:
    any of them
}