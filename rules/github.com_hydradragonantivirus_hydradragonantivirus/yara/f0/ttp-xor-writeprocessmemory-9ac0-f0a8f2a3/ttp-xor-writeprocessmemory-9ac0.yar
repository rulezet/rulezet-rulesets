rule TTP_XOR_WriteProcessMemory_9ac0 {
  strings:
    $key_9ac0 = { cd b2 [2] ff 90 [2] f9 a5 [2] d7 a5 [2] e8 b9 }

  condition:
    any of them
}