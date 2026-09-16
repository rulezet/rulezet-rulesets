rule TTP_XOR_WriteProcessMemory_92cd {
  strings:
    $key_92cd = { c5 bf [2] f7 9d [2] f1 a8 [2] df a8 [2] e0 b4 }

  condition:
    any of them
}