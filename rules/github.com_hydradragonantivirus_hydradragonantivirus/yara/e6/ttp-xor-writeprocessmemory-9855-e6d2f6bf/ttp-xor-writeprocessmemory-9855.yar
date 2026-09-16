rule TTP_XOR_WriteProcessMemory_9855 {
  strings:
    $key_9855 = { cf 27 [2] fd 05 [2] fb 30 [2] d5 30 [2] ea 2c }

  condition:
    any of them
}