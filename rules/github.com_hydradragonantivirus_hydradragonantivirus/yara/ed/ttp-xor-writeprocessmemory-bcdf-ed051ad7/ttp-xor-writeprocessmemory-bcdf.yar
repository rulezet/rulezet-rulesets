rule TTP_XOR_WriteProcessMemory_bcdf {
  strings:
    $key_bcdf = { eb ad [2] d9 8f [2] df ba [2] f1 ba [2] ce a6 }

  condition:
    any of them
}