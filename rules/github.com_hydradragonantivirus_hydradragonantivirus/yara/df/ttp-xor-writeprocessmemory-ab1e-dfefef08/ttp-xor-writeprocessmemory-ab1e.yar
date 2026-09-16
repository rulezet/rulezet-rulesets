rule TTP_XOR_WriteProcessMemory_ab1e {
  strings:
    $key_ab1e = { fc 6c [2] ce 4e [2] c8 7b [2] e6 7b [2] d9 67 }

  condition:
    any of them
}