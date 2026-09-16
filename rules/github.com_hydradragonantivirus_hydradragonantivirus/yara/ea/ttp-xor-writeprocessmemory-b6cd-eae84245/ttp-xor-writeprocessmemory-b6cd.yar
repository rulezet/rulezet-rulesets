rule TTP_XOR_WriteProcessMemory_b6cd {
  strings:
    $key_b6cd = { e1 bf [2] d3 9d [2] d5 a8 [2] fb a8 [2] c4 b4 }

  condition:
    any of them
}