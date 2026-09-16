rule TTP_XOR_WriteProcessMemory_87df {
  strings:
    $key_87df = { d0 ad [2] e2 8f [2] e4 ba [2] ca ba [2] f5 a6 }

  condition:
    any of them
}