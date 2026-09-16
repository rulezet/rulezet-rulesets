rule TTP_XOR_WriteProcessMemory_997b {
  strings:
    $key_997b = { ce 09 [2] fc 2b [2] fa 1e [2] d4 1e [2] eb 02 }

  condition:
    any of them
}