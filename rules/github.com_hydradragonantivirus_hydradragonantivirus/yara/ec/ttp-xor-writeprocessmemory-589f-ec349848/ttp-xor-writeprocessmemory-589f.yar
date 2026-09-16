rule TTP_XOR_WriteProcessMemory_589f {
  strings:
    $key_589f = { 0f ed [2] 3d cf [2] 3b fa [2] 15 fa [2] 2a e6 }

  condition:
    any of them
}