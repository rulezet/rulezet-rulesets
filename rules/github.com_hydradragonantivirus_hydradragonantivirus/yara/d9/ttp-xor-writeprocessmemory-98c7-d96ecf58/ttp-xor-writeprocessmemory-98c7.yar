rule TTP_XOR_WriteProcessMemory_98c7 {
  strings:
    $key_98c7 = { cf b5 [2] fd 97 [2] fb a2 [2] d5 a2 [2] ea be }

  condition:
    any of them
}