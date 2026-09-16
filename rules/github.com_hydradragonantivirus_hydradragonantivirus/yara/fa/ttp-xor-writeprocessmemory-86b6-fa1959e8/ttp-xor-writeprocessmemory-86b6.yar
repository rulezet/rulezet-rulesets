rule TTP_XOR_WriteProcessMemory_86b6 {
  strings:
    $key_86b6 = { d1 c4 [2] e3 e6 [2] e5 d3 [2] cb d3 [2] f4 cf }

  condition:
    any of them
}