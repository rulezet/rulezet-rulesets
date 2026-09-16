rule TTP_XOR_WriteProcessMemory_1a9f {
  strings:
    $key_1a9f = { 4d ed [2] 7f cf [2] 79 fa [2] 57 fa [2] 68 e6 }

  condition:
    any of them
}