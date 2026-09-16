rule TTP_XOR_WriteProcessMemory_9796 {
  strings:
    $key_9796 = { c0 e4 [2] f2 c6 [2] f4 f3 [2] da f3 [2] e5 ef }

  condition:
    any of them
}