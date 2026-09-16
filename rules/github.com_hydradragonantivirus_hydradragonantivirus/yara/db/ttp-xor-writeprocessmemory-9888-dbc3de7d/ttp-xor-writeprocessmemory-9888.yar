rule TTP_XOR_WriteProcessMemory_9888 {
  strings:
    $key_9888 = { cf fa [2] fd d8 [2] fb ed [2] d5 ed [2] ea f1 }

  condition:
    any of them
}