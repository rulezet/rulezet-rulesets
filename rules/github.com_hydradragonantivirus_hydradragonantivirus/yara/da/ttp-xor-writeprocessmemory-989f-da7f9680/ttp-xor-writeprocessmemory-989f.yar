rule TTP_XOR_WriteProcessMemory_989f {
  strings:
    $key_989f = { cf ed [2] fd cf [2] fb fa [2] d5 fa [2] ea e6 }

  condition:
    any of them
}