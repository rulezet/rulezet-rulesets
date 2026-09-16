rule TTP_XOR_WriteProcessMemory_93a3 {
  strings:
    $key_93a3 = { c4 d1 [2] f6 f3 [2] f0 c6 [2] de c6 [2] e1 da }

  condition:
    any of them
}