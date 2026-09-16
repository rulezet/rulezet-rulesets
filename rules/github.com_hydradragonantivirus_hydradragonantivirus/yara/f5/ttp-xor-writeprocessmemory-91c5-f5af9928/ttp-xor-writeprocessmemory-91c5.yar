rule TTP_XOR_WriteProcessMemory_91c5 {
  strings:
    $key_91c5 = { c6 b7 [2] f4 95 [2] f2 a0 [2] dc a0 [2] e3 bc }

  condition:
    any of them
}