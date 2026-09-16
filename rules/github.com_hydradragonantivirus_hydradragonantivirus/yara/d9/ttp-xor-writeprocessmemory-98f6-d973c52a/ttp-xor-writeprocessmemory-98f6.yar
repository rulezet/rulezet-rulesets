rule TTP_XOR_WriteProcessMemory_98f6 {
  strings:
    $key_98f6 = { cf 84 [2] fd a6 [2] fb 93 [2] d5 93 [2] ea 8f }

  condition:
    any of them
}