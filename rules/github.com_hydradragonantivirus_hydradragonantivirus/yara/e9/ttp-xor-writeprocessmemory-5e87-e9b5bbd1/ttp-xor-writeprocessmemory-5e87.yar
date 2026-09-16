rule TTP_XOR_WriteProcessMemory_5e87 {
  strings:
    $key_5e87 = { 09 f5 [2] 3b d7 [2] 3d e2 [2] 13 e2 [2] 2c fe }

  condition:
    any of them
}