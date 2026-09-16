rule TTP_XOR_WriteProcessMemory_8e3f {
  strings:
    $key_8e3f = { d9 4d [2] eb 6f [2] ed 5a [2] c3 5a [2] fc 46 }

  condition:
    any of them
}