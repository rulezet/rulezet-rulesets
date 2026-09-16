rule TTP_XOR_WriteProcessMemory_e687 {
  strings:
    $key_e687 = { b1 f5 [2] 83 d7 [2] 85 e2 [2] ab e2 [2] 94 fe }

  condition:
    any of them
}