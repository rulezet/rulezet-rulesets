rule TTP_XOR_WriteProcessMemory_9873 {
  strings:
    $key_9873 = { cf 01 [2] fd 23 [2] fb 16 [2] d5 16 [2] ea 0a }

  condition:
    any of them
}