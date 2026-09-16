rule TTP_XOR_WriteProcessMemory_94cd {
  strings:
    $key_94cd = { c3 bf [2] f1 9d [2] f7 a8 [2] d9 a8 [2] e6 b4 }

  condition:
    any of them
}