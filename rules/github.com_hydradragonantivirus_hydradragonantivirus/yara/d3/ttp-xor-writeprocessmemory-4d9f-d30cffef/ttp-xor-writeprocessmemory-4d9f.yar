rule TTP_XOR_WriteProcessMemory_4d9f {
  strings:
    $key_4d9f = { 1a ed [2] 28 cf [2] 2e fa [2] 00 fa [2] 3f e6 }

  condition:
    any of them
}