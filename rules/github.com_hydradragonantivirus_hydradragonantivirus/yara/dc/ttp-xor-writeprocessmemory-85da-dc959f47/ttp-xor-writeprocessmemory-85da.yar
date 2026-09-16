rule TTP_XOR_WriteProcessMemory_85da {
  strings:
    $key_85da = { d2 a8 [2] e0 8a [2] e6 bf [2] c8 bf [2] f7 a3 }

  condition:
    any of them
}