rule TTP_XOR_WriteProcessMemory_229f {
  strings:
    $key_229f = { 75 ed [2] 47 cf [2] 41 fa [2] 6f fa [2] 50 e6 }

  condition:
    any of them
}