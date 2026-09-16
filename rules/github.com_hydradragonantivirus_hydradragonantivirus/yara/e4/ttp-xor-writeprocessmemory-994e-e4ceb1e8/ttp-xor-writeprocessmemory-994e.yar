rule TTP_XOR_WriteProcessMemory_994e {
  strings:
    $key_994e = { ce 3c [2] fc 1e [2] fa 2b [2] d4 2b [2] eb 37 }

  condition:
    any of them
}