rule TTP_XOR_WriteProcessMemory_c99f {
  strings:
    $key_c99f = { 9e ed [2] ac cf [2] aa fa [2] 84 fa [2] bb e6 }

  condition:
    any of them
}