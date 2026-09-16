rule TTP_XOR_WriteProcessMemory_839f {
  strings:
    $key_839f = { d4 ed [2] e6 cf [2] e0 fa [2] ce fa [2] f1 e6 }

  condition:
    any of them
}