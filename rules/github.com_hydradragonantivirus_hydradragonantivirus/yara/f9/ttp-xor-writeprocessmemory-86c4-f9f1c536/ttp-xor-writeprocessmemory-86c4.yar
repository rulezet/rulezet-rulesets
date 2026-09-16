rule TTP_XOR_WriteProcessMemory_86c4 {
  strings:
    $key_86c4 = { d1 b6 [2] e3 94 [2] e5 a1 [2] cb a1 [2] f4 bd }

  condition:
    any of them
}