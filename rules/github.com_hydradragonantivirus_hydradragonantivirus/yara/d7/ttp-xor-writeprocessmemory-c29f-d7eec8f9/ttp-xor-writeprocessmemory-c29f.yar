rule TTP_XOR_WriteProcessMemory_c29f {
  strings:
    $key_c29f = { 95 ed [2] a7 cf [2] a1 fa [2] 8f fa [2] b0 e6 }

  condition:
    any of them
}