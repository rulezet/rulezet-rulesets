rule TTP_XOR_WriteProcessMemory_a2df {
  strings:
    $key_a2df = { f5 ad [2] c7 8f [2] c1 ba [2] ef ba [2] d0 a6 }

  condition:
    any of them
}