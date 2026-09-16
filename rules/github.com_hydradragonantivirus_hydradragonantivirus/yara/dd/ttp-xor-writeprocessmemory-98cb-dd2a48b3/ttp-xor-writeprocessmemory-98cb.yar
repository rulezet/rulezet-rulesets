rule TTP_XOR_WriteProcessMemory_98cb {
  strings:
    $key_98cb = { cf b9 [2] fd 9b [2] fb ae [2] d5 ae [2] ea b2 }

  condition:
    any of them
}