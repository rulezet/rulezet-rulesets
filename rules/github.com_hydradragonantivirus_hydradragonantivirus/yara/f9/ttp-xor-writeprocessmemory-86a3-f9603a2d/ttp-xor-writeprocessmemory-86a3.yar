rule TTP_XOR_WriteProcessMemory_86a3 {
  strings:
    $key_86a3 = { d1 d1 [2] e3 f3 [2] e5 c6 [2] cb c6 [2] f4 da }

  condition:
    any of them
}