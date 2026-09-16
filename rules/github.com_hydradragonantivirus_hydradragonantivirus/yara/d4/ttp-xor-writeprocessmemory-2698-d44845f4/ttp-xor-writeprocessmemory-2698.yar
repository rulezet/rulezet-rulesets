rule TTP_XOR_WriteProcessMemory_2698 {
  strings:
    $key_2698 = { 71 ea [2] 43 c8 [2] 45 fd [2] 6b fd [2] 54 e1 }

  condition:
    any of them
}