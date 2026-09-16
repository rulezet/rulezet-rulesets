rule TTP_XOR_WriteProcessMemory_8e90 {
  strings:
    $key_8e90 = { d9 e2 [2] eb c0 [2] ed f5 [2] c3 f5 [2] fc e9 }

  condition:
    any of them
}