rule TTP_XOR_WriteProcessMemory_980f {
  strings:
    $key_980f = { cf 7d [2] fd 5f [2] fb 6a [2] d5 6a [2] ea 76 }

  condition:
    any of them
}