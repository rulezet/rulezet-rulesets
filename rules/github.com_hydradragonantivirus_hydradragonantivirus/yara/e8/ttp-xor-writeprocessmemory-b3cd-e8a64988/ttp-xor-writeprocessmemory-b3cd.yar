rule TTP_XOR_WriteProcessMemory_b3cd {
  strings:
    $key_b3cd = { e4 bf [2] d6 9d [2] d0 a8 [2] fe a8 [2] c1 b4 }

  condition:
    any of them
}