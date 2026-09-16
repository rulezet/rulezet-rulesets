rule TTP_XOR_WriteProcessMemory_84cd {
  strings:
    $key_84cd = { d3 bf [2] e1 9d [2] e7 a8 [2] c9 a8 [2] f6 b4 }

  condition:
    any of them
}