rule TTP_XOR_WriteProcessMemory_3687 {
  strings:
    $key_3687 = { 61 f5 [2] 53 d7 [2] 55 e2 [2] 7b e2 [2] 44 fe }

  condition:
    any of them
}