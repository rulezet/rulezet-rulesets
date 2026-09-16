rule TTP_XOR_WriteProcessMemory_92df {
  strings:
    $key_92df = { c5 ad [2] f7 8f [2] f1 ba [2] df ba [2] e0 a6 }

  condition:
    any of them
}