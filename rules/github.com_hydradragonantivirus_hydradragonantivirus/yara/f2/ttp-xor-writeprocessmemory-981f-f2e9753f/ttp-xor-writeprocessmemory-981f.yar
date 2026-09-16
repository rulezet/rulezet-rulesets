rule TTP_XOR_WriteProcessMemory_981f {
  strings:
    $key_981f = { cf 6d [2] fd 4f [2] fb 7a [2] d5 7a [2] ea 66 }

  condition:
    any of them
}