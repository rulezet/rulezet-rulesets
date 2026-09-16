rule TTP_XOR_WriteProcessMemory_bcab {
  strings:
    $key_bcab = { eb d9 [2] d9 fb [2] df ce [2] f1 ce [2] ce d2 }

  condition:
    any of them
}