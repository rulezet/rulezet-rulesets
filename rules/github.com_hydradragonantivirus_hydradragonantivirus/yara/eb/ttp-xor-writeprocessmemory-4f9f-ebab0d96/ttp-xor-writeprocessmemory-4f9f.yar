rule TTP_XOR_WriteProcessMemory_4f9f {
  strings:
    $key_4f9f = { 18 ed [2] 2a cf [2] 2c fa [2] 02 fa [2] 3d e6 }

  condition:
    any of them
}