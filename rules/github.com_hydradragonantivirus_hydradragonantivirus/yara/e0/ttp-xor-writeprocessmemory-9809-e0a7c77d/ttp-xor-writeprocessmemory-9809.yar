rule TTP_XOR_WriteProcessMemory_9809 {
  strings:
    $key_9809 = { cf 7b [2] fd 59 [2] fb 6c [2] d5 6c [2] ea 70 }

  condition:
    any of them
}