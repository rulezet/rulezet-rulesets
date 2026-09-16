rule TTP_XOR_WriteProcessMemory_86f3 {
  strings:
    $key_86f3 = { d1 81 [2] e3 a3 [2] e5 96 [2] cb 96 [2] f4 8a }

  condition:
    any of them
}