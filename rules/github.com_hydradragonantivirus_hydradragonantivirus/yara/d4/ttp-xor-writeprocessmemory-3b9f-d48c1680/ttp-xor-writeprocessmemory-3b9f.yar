rule TTP_XOR_WriteProcessMemory_3b9f {
  strings:
    $key_3b9f = { 6c ed [2] 5e cf [2] 58 fa [2] 76 fa [2] 49 e6 }

  condition:
    any of them
}