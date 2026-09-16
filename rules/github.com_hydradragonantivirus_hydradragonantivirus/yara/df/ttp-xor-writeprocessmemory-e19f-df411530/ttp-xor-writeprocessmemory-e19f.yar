rule TTP_XOR_WriteProcessMemory_e19f {
  strings:
    $key_e19f = { b6 ed [2] 84 cf [2] 82 fa [2] ac fa [2] 93 e6 }

  condition:
    any of them
}