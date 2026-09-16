rule TTP_XOR_WriteProcessMemory_9896 {
  strings:
    $key_9896 = { cf e4 [2] fd c6 [2] fb f3 [2] d5 f3 [2] ea ef }

  condition:
    any of them
}