rule TTP_XOR_WriteProcessMemory_a6df {
  strings:
    $key_a6df = { f1 ad [2] c3 8f [2] c5 ba [2] eb ba [2] d4 a6 }

  condition:
    any of them
}