rule TTP_XOR_WriteProcessMemory_8e19 {
  strings:
    $key_8e19 = { d9 6b [2] eb 49 [2] ed 7c [2] c3 7c [2] fc 60 }

  condition:
    any of them
}