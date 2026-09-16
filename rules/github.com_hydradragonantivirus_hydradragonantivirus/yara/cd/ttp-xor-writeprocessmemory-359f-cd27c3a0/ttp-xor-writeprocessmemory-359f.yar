rule TTP_XOR_WriteProcessMemory_359f {
  strings:
    $key_359f = { 62 ed [2] 50 cf [2] 56 fa [2] 78 fa [2] 47 e6 }

  condition:
    any of them
}