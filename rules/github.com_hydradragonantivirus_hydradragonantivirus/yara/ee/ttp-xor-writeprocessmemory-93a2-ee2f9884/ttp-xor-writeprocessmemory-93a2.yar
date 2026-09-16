rule TTP_XOR_WriteProcessMemory_93a2 {
  strings:
    $key_93a2 = { c4 d0 [2] f6 f2 [2] f0 c7 [2] de c7 [2] e1 db }

  condition:
    any of them
}