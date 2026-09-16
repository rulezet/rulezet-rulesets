rule TTP_XOR_WriteProcessMemory_98f8 {
  strings:
    $key_98f8 = { cf 8a [2] fd a8 [2] fb 9d [2] d5 9d [2] ea 81 }

  condition:
    any of them
}