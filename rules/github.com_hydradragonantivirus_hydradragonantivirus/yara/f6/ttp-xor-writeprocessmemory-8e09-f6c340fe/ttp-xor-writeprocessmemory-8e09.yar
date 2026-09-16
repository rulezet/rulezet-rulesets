rule TTP_XOR_WriteProcessMemory_8e09 {
  strings:
    $key_8e09 = { d9 7b [2] eb 59 [2] ed 6c [2] c3 6c [2] fc 70 }

  condition:
    any of them
}