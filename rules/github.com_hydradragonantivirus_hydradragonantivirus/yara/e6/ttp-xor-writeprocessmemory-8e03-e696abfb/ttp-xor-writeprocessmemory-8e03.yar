rule TTP_XOR_WriteProcessMemory_8e03 {
  strings:
    $key_8e03 = { d9 71 [2] eb 53 [2] ed 66 [2] c3 66 [2] fc 7a }

  condition:
    any of them
}