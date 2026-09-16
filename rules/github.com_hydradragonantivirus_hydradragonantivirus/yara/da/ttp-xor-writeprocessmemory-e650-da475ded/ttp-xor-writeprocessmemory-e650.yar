rule TTP_XOR_WriteProcessMemory_e650 {
  strings:
    $key_e650 = { b1 22 [2] 83 00 [2] 85 35 [2] ab 35 [2] 94 29 }

  condition:
    any of them
}