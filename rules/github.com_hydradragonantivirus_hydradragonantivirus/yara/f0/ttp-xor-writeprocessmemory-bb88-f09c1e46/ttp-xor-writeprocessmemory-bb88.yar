rule TTP_XOR_WriteProcessMemory_bb88 {
  strings:
    $key_bb88 = { ec fa [2] de d8 [2] d8 ed [2] f6 ed [2] c9 f1 }

  condition:
    any of them
}