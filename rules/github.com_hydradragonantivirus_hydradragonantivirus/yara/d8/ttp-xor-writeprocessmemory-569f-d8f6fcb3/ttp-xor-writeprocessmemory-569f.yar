rule TTP_XOR_WriteProcessMemory_569f {
  strings:
    $key_569f = { 01 ed [2] 33 cf [2] 35 fa [2] 1b fa [2] 24 e6 }

  condition:
    any of them
}