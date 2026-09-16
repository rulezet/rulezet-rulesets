rule TTP_XOR_WriteProcessMemory_84b5 {
  strings:
    $key_84b5 = { d3 c7 [2] e1 e5 [2] e7 d0 [2] c9 d0 [2] f6 cc }

  condition:
    any of them
}