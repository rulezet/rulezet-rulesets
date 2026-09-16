rule TTP_XOR_WriteProcessMemory_9810 {
  strings:
    $key_9810 = { cf 62 [2] fd 40 [2] fb 75 [2] d5 75 [2] ea 69 }

  condition:
    any of them
}