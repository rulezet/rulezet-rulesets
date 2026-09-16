rule TTP_XOR_WriteProcessMemory_7a87 {
  strings:
    $key_7a87 = { 2d f5 [2] 1f d7 [2] 19 e2 [2] 37 e2 [2] 08 fe }

  condition:
    any of them
}