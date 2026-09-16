rule TTP_XOR_WriteProcessMemory_99df {
  strings:
    $key_99df = { ce ad [2] fc 8f [2] fa ba [2] d4 ba [2] eb a6 }

  condition:
    any of them
}