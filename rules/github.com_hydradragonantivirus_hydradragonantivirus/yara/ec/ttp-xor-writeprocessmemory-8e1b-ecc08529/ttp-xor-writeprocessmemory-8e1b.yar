rule TTP_XOR_WriteProcessMemory_8e1b {
  strings:
    $key_8e1b = { d9 69 [2] eb 4b [2] ed 7e [2] c3 7e [2] fc 62 }

  condition:
    any of them
}