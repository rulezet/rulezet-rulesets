rule TTP_XOR_WriteProcessMemory_939f {
  strings:
    $key_939f = { c4 ed [2] f6 cf [2] f0 fa [2] de fa [2] e1 e6 }

  condition:
    any of them
}