rule TTP_XOR_WriteProcessMemory_984a {
  strings:
    $key_984a = { cf 38 [2] fd 1a [2] fb 2f [2] d5 2f [2] ea 33 }

  condition:
    any of them
}