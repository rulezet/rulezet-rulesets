rule TTP_XOR_WriteProcessMemory_86d5 {
  strings:
    $key_86d5 = { d1 a7 [2] e3 85 [2] e5 b0 [2] cb b0 [2] f4 ac }

  condition:
    any of them
}