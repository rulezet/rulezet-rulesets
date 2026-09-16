rule TTP_XOR_WriteProcessMemory_9876 {
  strings:
    $key_9876 = { cf 04 [2] fd 26 [2] fb 13 [2] d5 13 [2] ea 0f }

  condition:
    any of them
}