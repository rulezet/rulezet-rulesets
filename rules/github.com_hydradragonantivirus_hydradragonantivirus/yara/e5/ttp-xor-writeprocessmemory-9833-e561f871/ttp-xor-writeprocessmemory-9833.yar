rule TTP_XOR_WriteProcessMemory_9833 {
  strings:
    $key_9833 = { cf 41 [2] fd 63 [2] fb 56 [2] d5 56 [2] ea 4a }

  condition:
    any of them
}