rule TTP_XOR_WriteProcessMemory_e651 {
  strings:
    $key_e651 = { b1 23 [2] 83 01 [2] 85 34 [2] ab 34 [2] 94 28 }

  condition:
    any of them
}