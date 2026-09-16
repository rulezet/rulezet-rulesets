rule TTP_XOR_WriteProcessMemory_2c9f {
  strings:
    $key_2c9f = { 7b ed [2] 49 cf [2] 4f fa [2] 61 fa [2] 5e e6 }

  condition:
    any of them
}