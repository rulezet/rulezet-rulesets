rule TTP_XOR_WriteProcessMemory_a08e {
  strings:
    $key_a08e = { f7 fc [2] c5 de [2] c3 eb [2] ed eb [2] d2 f7 }

  condition:
    any of them
}