rule TTP_XOR_WriteProcessMemory_8ec4 {
  strings:
    $key_8ec4 = { d9 b6 [2] eb 94 [2] ed a1 [2] c3 a1 [2] fc bd }

  condition:
    any of them
}