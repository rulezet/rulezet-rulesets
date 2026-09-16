rule TTP_XOR_WriteProcessMemory_8ed0 {
  strings:
    $key_8ed0 = { d9 a2 [2] eb 80 [2] ed b5 [2] c3 b5 [2] fc a9 }

  condition:
    any of them
}