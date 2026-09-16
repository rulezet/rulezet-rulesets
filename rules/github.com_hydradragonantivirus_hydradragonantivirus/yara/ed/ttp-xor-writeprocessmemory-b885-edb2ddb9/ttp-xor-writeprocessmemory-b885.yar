rule TTP_XOR_WriteProcessMemory_b885 {
  strings:
    $key_b885 = { ef f7 [2] dd d5 [2] db e0 [2] f5 e0 [2] ca fc }

  condition:
    any of them
}