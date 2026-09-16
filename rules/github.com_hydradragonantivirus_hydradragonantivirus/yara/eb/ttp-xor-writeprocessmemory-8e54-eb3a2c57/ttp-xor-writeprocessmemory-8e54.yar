rule TTP_XOR_WriteProcessMemory_8e54 {
  strings:
    $key_8e54 = { d9 26 [2] eb 04 [2] ed 31 [2] c3 31 [2] fc 2d }

  condition:
    any of them
}