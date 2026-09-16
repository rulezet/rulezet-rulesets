rule TTP_XOR_WriteProcessMemory_5d9f {
  strings:
    $key_5d9f = { 0a ed [2] 38 cf [2] 3e fa [2] 10 fa [2] 2f e6 }

  condition:
    any of them
}