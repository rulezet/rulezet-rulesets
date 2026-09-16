rule TTP_XOR_WriteProcessMemory_90df {
  strings:
    $key_90df = { c7 ad [2] f5 8f [2] f3 ba [2] dd ba [2] e2 a6 }

  condition:
    any of them
}