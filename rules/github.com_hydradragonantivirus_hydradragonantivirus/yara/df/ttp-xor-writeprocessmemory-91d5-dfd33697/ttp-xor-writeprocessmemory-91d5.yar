rule TTP_XOR_WriteProcessMemory_91d5 {
  strings:
    $key_91d5 = { c6 a7 [2] f4 85 [2] f2 b0 [2] dc b0 [2] e3 ac }

  condition:
    any of them
}