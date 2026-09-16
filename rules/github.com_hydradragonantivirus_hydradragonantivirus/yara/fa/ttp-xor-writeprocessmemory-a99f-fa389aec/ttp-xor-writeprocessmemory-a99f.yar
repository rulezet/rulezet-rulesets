rule TTP_XOR_WriteProcessMemory_a99f {
  strings:
    $key_a99f = { fe ed [2] cc cf [2] ca fa [2] e4 fa [2] db e6 }

  condition:
    any of them
}