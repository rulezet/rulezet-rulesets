rule TTP_XOR_WriteProcessMemory_3a9f {
  strings:
    $key_3a9f = { 6d ed [2] 5f cf [2] 59 fa [2] 77 fa [2] 48 e6 }

  condition:
    any of them
}