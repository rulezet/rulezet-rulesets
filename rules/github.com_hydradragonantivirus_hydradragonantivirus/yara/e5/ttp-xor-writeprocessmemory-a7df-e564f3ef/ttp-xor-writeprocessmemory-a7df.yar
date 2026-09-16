rule TTP_XOR_WriteProcessMemory_a7df {
  strings:
    $key_a7df = { f0 ad [2] c2 8f [2] c4 ba [2] ea ba [2] d5 a6 }

  condition:
    any of them
}