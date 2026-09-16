rule TTP_XOR_WriteProcessMemory_98df {
  strings:
    $key_98df = { cf ad [2] fd 8f [2] fb ba [2] d5 ba [2] ea a6 }

  condition:
    any of them
}