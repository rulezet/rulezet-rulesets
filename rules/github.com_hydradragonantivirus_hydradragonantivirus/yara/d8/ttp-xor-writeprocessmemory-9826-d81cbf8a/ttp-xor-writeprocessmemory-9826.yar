rule TTP_XOR_WriteProcessMemory_9826 {
  strings:
    $key_9826 = { cf 54 [2] fd 76 [2] fb 43 [2] d5 43 [2] ea 5f }

  condition:
    any of them
}