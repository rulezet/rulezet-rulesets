rule TTP_XOR_WriteProcessMemory_8659 {
  strings:
    $key_8659 = { d1 2b [2] e3 09 [2] e5 3c [2] cb 3c [2] f4 20 }

  condition:
    any of them
}