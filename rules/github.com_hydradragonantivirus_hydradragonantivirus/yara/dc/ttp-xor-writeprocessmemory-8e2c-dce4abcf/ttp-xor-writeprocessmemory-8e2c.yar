rule TTP_XOR_WriteProcessMemory_8e2c {
  strings:
    $key_8e2c = { d9 5e [2] eb 7c [2] ed 49 [2] c3 49 [2] fc 55 }

  condition:
    any of them
}