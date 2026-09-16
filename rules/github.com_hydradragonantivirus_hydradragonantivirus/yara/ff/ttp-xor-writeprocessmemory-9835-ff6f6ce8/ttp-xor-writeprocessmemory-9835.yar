rule TTP_XOR_WriteProcessMemory_9835 {
  strings:
    $key_9835 = { cf 47 [2] fd 65 [2] fb 50 [2] d5 50 [2] ea 4c }

  condition:
    any of them
}