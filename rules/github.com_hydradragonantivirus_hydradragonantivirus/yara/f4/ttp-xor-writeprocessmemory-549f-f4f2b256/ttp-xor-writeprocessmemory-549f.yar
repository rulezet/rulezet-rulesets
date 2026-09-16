rule TTP_XOR_WriteProcessMemory_549f {
  strings:
    $key_549f = { 03 ed [2] 31 cf [2] 37 fa [2] 19 fa [2] 26 e6 }

  condition:
    any of them
}