rule TTP_XOR_WriteProcessMemory_49df {
  strings:
    $key_49df = { 1e ad [2] 2c 8f [2] 2a ba [2] 04 ba [2] 3b a6 }

  condition:
    any of them
}