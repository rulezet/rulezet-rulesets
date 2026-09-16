rule TTP_XOR_WriteProcessMemory_abf9 {
  strings:
    $key_abf9 = { fc 8b [2] ce a9 [2] c8 9c [2] e6 9c [2] d9 80 }

  condition:
    any of them
}