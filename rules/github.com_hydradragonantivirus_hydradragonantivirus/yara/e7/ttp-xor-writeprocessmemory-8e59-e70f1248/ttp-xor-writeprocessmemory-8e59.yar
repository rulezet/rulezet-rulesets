rule TTP_XOR_WriteProcessMemory_8e59 {
  strings:
    $key_8e59 = { d9 2b [2] eb 09 [2] ed 3c [2] c3 3c [2] fc 20 }

  condition:
    any of them
}