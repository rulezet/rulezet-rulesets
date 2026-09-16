rule TTP_XOR_WriteProcessMemory_e672 {
  strings:
    $key_e672 = { b1 00 [2] 83 22 [2] 85 17 [2] ab 17 [2] 94 0b }

  condition:
    any of them
}