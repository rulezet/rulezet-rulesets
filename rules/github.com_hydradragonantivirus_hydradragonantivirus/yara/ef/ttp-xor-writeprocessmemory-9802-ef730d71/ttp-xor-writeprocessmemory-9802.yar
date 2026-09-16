rule TTP_XOR_WriteProcessMemory_9802 {
  strings:
    $key_9802 = { cf 70 [2] fd 52 [2] fb 67 [2] d5 67 [2] ea 7b }

  condition:
    any of them
}