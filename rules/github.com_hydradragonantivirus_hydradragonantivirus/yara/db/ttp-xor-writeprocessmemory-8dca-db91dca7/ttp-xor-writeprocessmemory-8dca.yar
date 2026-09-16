rule TTP_XOR_WriteProcessMemory_8dca {
  strings:
    $key_8dca = { da b8 [2] e8 9a [2] ee af [2] c0 af [2] ff b3 }

  condition:
    any of them
}