rule TTP_XOR_WriteProcessMemory_a987 {
  strings:
    $key_a987 = { fe f5 [2] cc d7 [2] ca e2 [2] e4 e2 [2] db fe }

  condition:
    any of them
}