rule TTP_XOR_WriteProcessMemory_81a3 {
  strings:
    $key_81a3 = { d6 d1 [2] e4 f3 [2] e2 c6 [2] cc c6 [2] f3 da }

  condition:
    any of them
}