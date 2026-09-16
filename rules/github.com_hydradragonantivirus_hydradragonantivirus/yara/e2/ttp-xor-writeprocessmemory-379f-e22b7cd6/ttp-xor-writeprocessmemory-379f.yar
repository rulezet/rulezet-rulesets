rule TTP_XOR_WriteProcessMemory_379f {
  strings:
    $key_379f = { 60 ed [2] 52 cf [2] 54 fa [2] 7a fa [2] 45 e6 }

  condition:
    any of them
}