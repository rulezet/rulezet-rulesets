rule TTP_XOR_WriteProcessMemory_8e6a {
  strings:
    $key_8e6a = { d9 18 [2] eb 3a [2] ed 0f [2] c3 0f [2] fc 13 }

  condition:
    any of them
}