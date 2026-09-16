rule TTP_XOR_WriteProcessMemory_8e7c {
  strings:
    $key_8e7c = { d9 0e [2] eb 2c [2] ed 19 [2] c3 19 [2] fc 05 }

  condition:
    any of them
}