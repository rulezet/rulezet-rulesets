rule TTP_XOR_WriteProcessMemory_419f {
  strings:
    $key_419f = { 16 ed [2] 24 cf [2] 22 fa [2] 0c fa [2] 33 e6 }

  condition:
    any of them
}