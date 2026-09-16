rule TTP_XOR_WriteProcessMemory_9856 {
  strings:
    $key_9856 = { cf 24 [2] fd 06 [2] fb 33 [2] d5 33 [2] ea 2f }

  condition:
    any of them
}