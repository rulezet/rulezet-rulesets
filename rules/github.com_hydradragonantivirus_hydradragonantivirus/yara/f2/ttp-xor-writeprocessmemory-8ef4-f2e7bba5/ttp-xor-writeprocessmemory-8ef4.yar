rule TTP_XOR_WriteProcessMemory_8ef4 {
  strings:
    $key_8ef4 = { d9 86 [2] eb a4 [2] ed 91 [2] c3 91 [2] fc 8d }

  condition:
    any of them
}