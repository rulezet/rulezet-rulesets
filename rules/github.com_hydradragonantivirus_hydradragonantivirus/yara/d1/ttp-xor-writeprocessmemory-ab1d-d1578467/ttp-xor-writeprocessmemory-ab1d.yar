rule TTP_XOR_WriteProcessMemory_ab1d {
  strings:
    $key_ab1d = { fc 6f [2] ce 4d [2] c8 78 [2] e6 78 [2] d9 64 }

  condition:
    any of them
}