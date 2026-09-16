rule TTP_XOR_WriteProcessMemory_e631 {
  strings:
    $key_e631 = { b1 43 [2] 83 61 [2] 85 54 [2] ab 54 [2] 94 48 }

  condition:
    any of them
}