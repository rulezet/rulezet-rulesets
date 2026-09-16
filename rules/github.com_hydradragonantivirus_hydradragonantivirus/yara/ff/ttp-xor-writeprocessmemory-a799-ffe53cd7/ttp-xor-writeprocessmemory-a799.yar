rule TTP_XOR_WriteProcessMemory_a799 {
  strings:
    $key_a799 = { f0 eb [2] c2 c9 [2] c4 fc [2] ea fc [2] d5 e0 }

  condition:
    any of them
}