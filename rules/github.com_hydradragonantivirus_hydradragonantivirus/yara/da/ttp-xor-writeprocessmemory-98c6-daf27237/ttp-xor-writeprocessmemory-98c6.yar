rule TTP_XOR_WriteProcessMemory_98c6 {
  strings:
    $key_98c6 = { cf b4 [2] fd 96 [2] fb a3 [2] d5 a3 [2] ea bf }

  condition:
    any of them
}