rule TTP_XOR_WriteProcessMemory_8e1d {
  strings:
    $key_8e1d = { d9 6f [2] eb 4d [2] ed 78 [2] c3 78 [2] fc 64 }

  condition:
    any of them
}