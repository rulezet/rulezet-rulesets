rule TTP_XOR_WriteProcessMemory_e641 {
  strings:
    $key_e641 = { b1 33 [2] 83 11 [2] 85 24 [2] ab 24 [2] 94 38 }

  condition:
    any of them
}