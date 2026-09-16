rule TTP_XOR_WriteProcessMemory_86ef {
  strings:
    $key_86ef = { d1 9d [2] e3 bf [2] e5 8a [2] cb 8a [2] f4 96 }

  condition:
    any of them
}