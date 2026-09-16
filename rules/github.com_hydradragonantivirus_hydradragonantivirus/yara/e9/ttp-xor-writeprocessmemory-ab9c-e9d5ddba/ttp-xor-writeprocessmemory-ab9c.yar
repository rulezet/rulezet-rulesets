rule TTP_XOR_WriteProcessMemory_ab9c {
  strings:
    $key_ab9c = { fc ee [2] ce cc [2] c8 f9 [2] e6 f9 [2] d9 e5 }

  condition:
    any of them
}