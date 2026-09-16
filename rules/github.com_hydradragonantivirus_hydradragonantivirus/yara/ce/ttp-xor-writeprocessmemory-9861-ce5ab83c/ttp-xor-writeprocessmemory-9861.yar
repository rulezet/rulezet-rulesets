rule TTP_XOR_WriteProcessMemory_9861 {
  strings:
    $key_9861 = { cf 13 [2] fd 31 [2] fb 04 [2] d5 04 [2] ea 18 }

  condition:
    any of them
}