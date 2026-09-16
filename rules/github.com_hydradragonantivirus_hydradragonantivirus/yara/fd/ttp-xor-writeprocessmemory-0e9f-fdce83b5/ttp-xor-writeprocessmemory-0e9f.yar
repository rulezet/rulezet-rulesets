rule TTP_XOR_WriteProcessMemory_0e9f {
  strings:
    $key_0e9f = { 59 ed [2] 6b cf [2] 6d fa [2] 43 fa [2] 7c e6 }

  condition:
    any of them
}