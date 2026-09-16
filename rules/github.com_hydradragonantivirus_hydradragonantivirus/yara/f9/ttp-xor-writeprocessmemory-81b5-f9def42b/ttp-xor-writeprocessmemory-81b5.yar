rule TTP_XOR_WriteProcessMemory_81b5 {
  strings:
    $key_81b5 = { d6 c7 [2] e4 e5 [2] e2 d0 [2] cc d0 [2] f3 cc }

  condition:
    any of them
}