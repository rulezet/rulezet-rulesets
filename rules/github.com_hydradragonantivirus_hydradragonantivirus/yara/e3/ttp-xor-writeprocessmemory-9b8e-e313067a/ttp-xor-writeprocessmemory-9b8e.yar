rule TTP_XOR_WriteProcessMemory_9b8e {
  strings:
    $key_9b8e = { cc fc [2] fe de [2] f8 eb [2] d6 eb [2] e9 f7 }

  condition:
    any of them
}