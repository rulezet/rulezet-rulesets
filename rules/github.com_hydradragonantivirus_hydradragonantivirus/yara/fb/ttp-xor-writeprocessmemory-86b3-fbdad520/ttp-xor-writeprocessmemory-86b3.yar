rule TTP_XOR_WriteProcessMemory_86b3 {
  strings:
    $key_86b3 = { d1 c1 [2] e3 e3 [2] e5 d6 [2] cb d6 [2] f4 ca }

  condition:
    any of them
}