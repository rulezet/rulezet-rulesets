rule TTP_XOR_WriteProcessMemory_ab8e {
  strings:
    $key_ab8e = { fc fc [2] ce de [2] c8 eb [2] e6 eb [2] d9 f7 }

  condition:
    any of them
}