rule TTP_XOR_WriteProcessMemory_c79f {
  strings:
    $key_c79f = { 90 ed [2] a2 cf [2] a4 fa [2] 8a fa [2] b5 e6 }

  condition:
    any of them
}