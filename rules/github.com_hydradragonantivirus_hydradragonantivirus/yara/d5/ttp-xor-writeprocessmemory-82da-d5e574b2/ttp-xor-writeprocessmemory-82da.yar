rule TTP_XOR_WriteProcessMemory_82da {
  strings:
    $key_82da = { d5 a8 [2] e7 8a [2] e1 bf [2] cf bf [2] f0 a3 }

  condition:
    any of them
}