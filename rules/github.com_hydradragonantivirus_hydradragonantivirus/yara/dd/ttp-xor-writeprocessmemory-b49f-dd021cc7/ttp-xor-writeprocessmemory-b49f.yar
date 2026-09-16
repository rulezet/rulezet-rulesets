rule TTP_XOR_WriteProcessMemory_b49f {
  strings:
    $key_b49f = { e3 ed [2] d1 cf [2] d7 fa [2] f9 fa [2] c6 e6 }

  condition:
    any of them
}