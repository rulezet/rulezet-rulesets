rule TTP_XOR_WriteProcessMemory_8e29 {
  strings:
    $key_8e29 = { d9 5b [2] eb 79 [2] ed 4c [2] c3 4c [2] fc 50 }

  condition:
    any of them
}