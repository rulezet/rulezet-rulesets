rule TTP_XOR_WriteProcessMemory_bb82 {
  strings:
    $key_bb82 = { ec f0 [2] de d2 [2] d8 e7 [2] f6 e7 [2] c9 fb }

  condition:
    any of them
}