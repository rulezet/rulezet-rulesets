rule TTP_XOR_WriteProcessMemory_a099 {
  strings:
    $key_a099 = { f7 eb [2] c5 c9 [2] c3 fc [2] ed fc [2] d2 e0 }

  condition:
    any of them
}