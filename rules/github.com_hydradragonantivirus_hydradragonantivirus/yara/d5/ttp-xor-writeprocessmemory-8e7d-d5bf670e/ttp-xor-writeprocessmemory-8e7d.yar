rule TTP_XOR_WriteProcessMemory_8e7d {
  strings:
    $key_8e7d = { d9 0f [2] eb 2d [2] ed 18 [2] c3 18 [2] fc 04 }

  condition:
    any of them
}