rule TTP_XOR_WriteProcessMemory_7c9f {
  strings:
    $key_7c9f = { 2b ed [2] 19 cf [2] 1f fa [2] 31 fa [2] 0e e6 }

  condition:
    any of them
}