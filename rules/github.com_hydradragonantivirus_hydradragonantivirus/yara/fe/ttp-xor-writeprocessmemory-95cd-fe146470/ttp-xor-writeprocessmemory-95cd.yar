rule TTP_XOR_WriteProcessMemory_95cd {
  strings:
    $key_95cd = { c2 bf [2] f0 9d [2] f6 a8 [2] d8 a8 [2] e7 b4 }

  condition:
    any of them
}