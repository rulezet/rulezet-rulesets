rule TTP_XOR_WriteProcessMemory_aaee {
  strings:
    $key_aaee = { fd 9c [2] cf be [2] c9 8b [2] e7 8b [2] d8 97 }

  condition:
    any of them
}