rule TTP_XOR_WriteProcessMemory_ed9f {
  strings:
    $key_ed9f = { ba ed [2] 88 cf [2] 8e fa [2] a0 fa [2] 9f e6 }

  condition:
    any of them
}