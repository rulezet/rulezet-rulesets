rule TTP_XOR_WriteProcessMemory_6b9f {
  strings:
    $key_6b9f = { 3c ed [2] 0e cf [2] 08 fa [2] 26 fa [2] 19 e6 }

  condition:
    any of them
}