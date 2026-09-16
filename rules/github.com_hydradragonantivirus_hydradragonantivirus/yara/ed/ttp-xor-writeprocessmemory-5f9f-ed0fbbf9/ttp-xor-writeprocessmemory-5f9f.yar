rule TTP_XOR_WriteProcessMemory_5f9f {
  strings:
    $key_5f9f = { 08 ed [2] 3a cf [2] 3c fa [2] 12 fa [2] 2d e6 }

  condition:
    any of them
}