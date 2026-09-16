rule TTP_XOR_WriteProcessMemory_8593 {
  strings:
    $key_8593 = { d2 e1 [2] e0 c3 [2] e6 f6 [2] c8 f6 [2] f7 ea }

  condition:
    any of them
}