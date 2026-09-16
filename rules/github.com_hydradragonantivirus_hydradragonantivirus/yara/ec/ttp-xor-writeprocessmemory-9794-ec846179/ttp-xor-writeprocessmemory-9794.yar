rule TTP_XOR_WriteProcessMemory_9794 {
  strings:
    $key_9794 = { c0 e6 [2] f2 c4 [2] f4 f1 [2] da f1 [2] e5 ed }

  condition:
    any of them
}