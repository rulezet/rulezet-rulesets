rule TTP_XOR_WriteProcessMemory_fe9f {
  strings:
    $key_fe9f = { a9 ed [2] 9b cf [2] 9d fa [2] b3 fa [2] 8c e6 }

  condition:
    any of them
}