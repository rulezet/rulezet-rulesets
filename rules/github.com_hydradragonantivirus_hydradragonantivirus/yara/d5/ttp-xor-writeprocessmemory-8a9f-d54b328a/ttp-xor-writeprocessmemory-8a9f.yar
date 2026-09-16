rule TTP_XOR_WriteProcessMemory_8a9f {
  strings:
    $key_8a9f = { dd ed [2] ef cf [2] e9 fa [2] c7 fa [2] f8 e6 }

  condition:
    any of them
}