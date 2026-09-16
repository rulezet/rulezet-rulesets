rule TTP_XOR_WriteProcessMemory_da9f {
  strings:
    $key_da9f = { 8d ed [2] bf cf [2] b9 fa [2] 97 fa [2] a8 e6 }

  condition:
    any of them
}