rule TTP_XOR_WriteProcessMemory_98f9 {
  strings:
    $key_98f9 = { cf 8b [2] fd a9 [2] fb 9c [2] d5 9c [2] ea 80 }

  condition:
    any of them
}