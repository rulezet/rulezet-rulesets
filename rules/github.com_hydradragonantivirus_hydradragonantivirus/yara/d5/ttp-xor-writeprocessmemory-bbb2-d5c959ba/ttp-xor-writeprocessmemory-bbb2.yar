rule TTP_XOR_WriteProcessMemory_bbb2 {
  strings:
    $key_bbb2 = { ec c0 [2] de e2 [2] d8 d7 [2] f6 d7 [2] c9 cb }

  condition:
    any of them
}