rule TTP_XOR_WriteProcessMemory_86da {
  strings:
    $key_86da = { d1 a8 [2] e3 8a [2] e5 bf [2] cb bf [2] f4 a3 }

  condition:
    any of them
}