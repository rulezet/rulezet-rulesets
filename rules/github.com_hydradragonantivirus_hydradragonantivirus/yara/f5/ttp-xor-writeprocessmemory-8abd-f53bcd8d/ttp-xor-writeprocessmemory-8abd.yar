rule TTP_XOR_WriteProcessMemory_8abd {
  strings:
    $key_8abd = { dd cf [2] ef ed [2] e9 d8 [2] c7 d8 [2] f8 c4 }

  condition:
    any of them
}