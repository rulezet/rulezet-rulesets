rule TTP_XOR_WriteProcessMemory_98e9 {
  strings:
    $key_98e9 = { cf 9b [2] fd b9 [2] fb 8c [2] d5 8c [2] ea 90 }

  condition:
    any of them
}