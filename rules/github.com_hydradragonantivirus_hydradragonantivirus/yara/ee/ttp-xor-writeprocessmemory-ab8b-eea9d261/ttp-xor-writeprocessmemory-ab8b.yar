rule TTP_XOR_WriteProcessMemory_ab8b {
  strings:
    $key_ab8b = { fc f9 [2] ce db [2] c8 ee [2] e6 ee [2] d9 f2 }

  condition:
    any of them
}