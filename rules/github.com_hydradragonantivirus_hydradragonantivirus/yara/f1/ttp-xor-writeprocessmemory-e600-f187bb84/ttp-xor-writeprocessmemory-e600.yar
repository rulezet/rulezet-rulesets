rule TTP_XOR_WriteProcessMemory_e600 {
  strings:
    $key_e600 = { b1 72 [2] 83 50 [2] 85 65 [2] ab 65 [2] 94 79 }

  condition:
    any of them
}