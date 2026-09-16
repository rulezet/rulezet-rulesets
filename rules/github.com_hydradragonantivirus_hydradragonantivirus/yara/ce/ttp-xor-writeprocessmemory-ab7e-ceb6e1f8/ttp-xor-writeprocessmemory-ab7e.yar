rule TTP_XOR_WriteProcessMemory_ab7e {
  strings:
    $key_ab7e = { fc 0c [2] ce 2e [2] c8 1b [2] e6 1b [2] d9 07 }

  condition:
    any of them
}