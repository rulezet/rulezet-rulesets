rule TTP_XOR_WriteProcessMemory_baac {
  strings:
    $key_baac = { ed de [2] df fc [2] d9 c9 [2] f7 c9 [2] c8 d5 }

  condition:
    any of them
}