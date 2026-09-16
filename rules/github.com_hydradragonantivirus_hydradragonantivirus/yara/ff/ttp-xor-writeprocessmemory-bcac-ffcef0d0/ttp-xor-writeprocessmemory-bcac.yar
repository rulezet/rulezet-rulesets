rule TTP_XOR_WriteProcessMemory_bcac {
  strings:
    $key_bcac = { eb de [2] d9 fc [2] df c9 [2] f1 c9 [2] ce d5 }

  condition:
    any of them
}