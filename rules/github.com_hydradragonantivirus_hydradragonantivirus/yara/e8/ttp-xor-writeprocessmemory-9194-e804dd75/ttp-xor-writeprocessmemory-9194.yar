rule TTP_XOR_WriteProcessMemory_9194 {
  strings:
    $key_9194 = { c6 e6 [2] f4 c4 [2] f2 f1 [2] dc f1 [2] e3 ed }

  condition:
    any of them
}