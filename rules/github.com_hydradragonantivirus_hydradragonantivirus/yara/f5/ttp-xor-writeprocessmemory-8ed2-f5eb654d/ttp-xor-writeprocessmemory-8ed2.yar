rule TTP_XOR_WriteProcessMemory_8ed2 {
  strings:
    $key_8ed2 = { d9 a0 [2] eb 82 [2] ed b7 [2] c3 b7 [2] fc ab }

  condition:
    any of them
}