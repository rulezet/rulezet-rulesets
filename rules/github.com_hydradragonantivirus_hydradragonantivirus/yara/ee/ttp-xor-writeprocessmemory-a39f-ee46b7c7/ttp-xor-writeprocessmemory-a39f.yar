rule TTP_XOR_WriteProcessMemory_a39f {
  strings:
    $key_a39f = { f4 ed [2] c6 cf [2] c0 fa [2] ee fa [2] d1 e6 }

  condition:
    any of them
}