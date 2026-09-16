rule TTP_XOR_WriteProcessMemory_e59f {
  strings:
    $key_e59f = { b2 ed [2] 80 cf [2] 86 fa [2] a8 fa [2] 97 e6 }

  condition:
    any of them
}