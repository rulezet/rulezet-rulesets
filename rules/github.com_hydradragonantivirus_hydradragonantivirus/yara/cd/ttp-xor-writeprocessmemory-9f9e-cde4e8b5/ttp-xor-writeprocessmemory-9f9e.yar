rule TTP_XOR_WriteProcessMemory_9f9e {
  strings:
    $key_9f9e = { c8 ec [2] fa ce [2] fc fb [2] d2 fb [2] ed e7 }

  condition:
    any of them
}