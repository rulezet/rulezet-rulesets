rule TTP_XOR_WriteProcessMemory_b09f {
  strings:
    $key_b09f = { e7 ed [2] d5 cf [2] d3 fa [2] fd fa [2] c2 e6 }

  condition:
    any of them
}