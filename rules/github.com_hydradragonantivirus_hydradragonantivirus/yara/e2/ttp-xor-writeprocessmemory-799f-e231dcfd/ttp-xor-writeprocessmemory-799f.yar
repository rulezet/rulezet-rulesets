rule TTP_XOR_WriteProcessMemory_799f {
  strings:
    $key_799f = { 2e ed [2] 1c cf [2] 1a fa [2] 34 fa [2] 0b e6 }

  condition:
    any of them
}