rule TTP_XOR_WriteProcessMemory_a0cd {
  strings:
    $key_a0cd = { f7 bf [2] c5 9d [2] c3 a8 [2] ed a8 [2] d2 b4 }

  condition:
    any of them
}