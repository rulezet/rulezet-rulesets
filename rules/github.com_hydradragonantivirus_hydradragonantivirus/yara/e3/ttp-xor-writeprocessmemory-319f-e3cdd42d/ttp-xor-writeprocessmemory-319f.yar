rule TTP_XOR_WriteProcessMemory_319f {
  strings:
    $key_319f = { 66 ed [2] 54 cf [2] 52 fa [2] 7c fa [2] 43 e6 }

  condition:
    any of them
}