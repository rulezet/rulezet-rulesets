rule TTP_XOR_WriteProcessMemory_8e39 {
  strings:
    $key_8e39 = { d9 4b [2] eb 69 [2] ed 5c [2] c3 5c [2] fc 40 }

  condition:
    any of them
}