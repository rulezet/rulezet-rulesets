rule TTP_XOR_WriteProcessMemory_ab2b {
  strings:
    $key_ab2b = { fc 59 [2] ce 7b [2] c8 4e [2] e6 4e [2] d9 52 }

  condition:
    any of them
}