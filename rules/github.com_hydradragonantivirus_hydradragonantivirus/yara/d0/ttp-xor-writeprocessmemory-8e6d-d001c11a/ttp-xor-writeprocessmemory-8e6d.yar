rule TTP_XOR_WriteProcessMemory_8e6d {
  strings:
    $key_8e6d = { d9 1f [2] eb 3d [2] ed 08 [2] c3 08 [2] fc 14 }

  condition:
    any of them
}