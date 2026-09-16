rule TTP_XOR_WriteProcessMemory_828e {
  strings:
    $key_828e = { d5 fc [2] e7 de [2] e1 eb [2] cf eb [2] f0 f7 }

  condition:
    any of them
}