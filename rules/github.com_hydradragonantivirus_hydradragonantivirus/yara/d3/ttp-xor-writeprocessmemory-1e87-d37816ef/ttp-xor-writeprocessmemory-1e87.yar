rule TTP_XOR_WriteProcessMemory_1e87 {
  strings:
    $key_1e87 = { 49 f5 [2] 7b d7 [2] 7d e2 [2] 53 e2 [2] 6c fe }

  condition:
    any of them
}