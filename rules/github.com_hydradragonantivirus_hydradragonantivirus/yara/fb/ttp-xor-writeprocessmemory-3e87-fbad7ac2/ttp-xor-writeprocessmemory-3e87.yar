rule TTP_XOR_WriteProcessMemory_3e87 {
  strings:
    $key_3e87 = { 69 f5 [2] 5b d7 [2] 5d e2 [2] 73 e2 [2] 4c fe }

  condition:
    any of them
}