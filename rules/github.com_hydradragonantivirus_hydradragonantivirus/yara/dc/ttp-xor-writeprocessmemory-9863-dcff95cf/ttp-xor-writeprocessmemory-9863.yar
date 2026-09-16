rule TTP_XOR_WriteProcessMemory_9863 {
  strings:
    $key_9863 = { cf 11 [2] fd 33 [2] fb 06 [2] d5 06 [2] ea 1a }

  condition:
    any of them
}