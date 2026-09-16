rule TTP_XOR_WriteProcessMemory_329f {
  strings:
    $key_329f = { 65 ed [2] 57 cf [2] 51 fa [2] 7f fa [2] 40 e6 }

  condition:
    any of them
}