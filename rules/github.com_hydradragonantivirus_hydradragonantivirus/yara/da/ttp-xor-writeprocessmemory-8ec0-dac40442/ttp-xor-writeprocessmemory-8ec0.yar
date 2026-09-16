rule TTP_XOR_WriteProcessMemory_8ec0 {
  strings:
    $key_8ec0 = { d9 b2 [2] eb 90 [2] ed a5 [2] c3 a5 [2] fc b9 }

  condition:
    any of them
}