rule TTP_XOR_WriteProcessMemory_7f9f {
  strings:
    $key_7f9f = { 28 ed [2] 1a cf [2] 1c fa [2] 32 fa [2] 0d e6 }

  condition:
    any of them
}