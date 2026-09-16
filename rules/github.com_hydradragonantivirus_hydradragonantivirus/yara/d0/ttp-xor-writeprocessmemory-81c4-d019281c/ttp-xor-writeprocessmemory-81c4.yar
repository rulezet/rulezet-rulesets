rule TTP_XOR_WriteProcessMemory_81c4 {
  strings:
    $key_81c4 = { d6 b6 [2] e4 94 [2] e2 a1 [2] cc a1 [2] f3 bd }

  condition:
    any of them
}