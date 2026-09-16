rule TTP_XOR_WriteProcessMemory_98e4 {
  strings:
    $key_98e4 = { cf 96 [2] fd b4 [2] fb 81 [2] d5 81 [2] ea 9d }

  condition:
    any of them
}