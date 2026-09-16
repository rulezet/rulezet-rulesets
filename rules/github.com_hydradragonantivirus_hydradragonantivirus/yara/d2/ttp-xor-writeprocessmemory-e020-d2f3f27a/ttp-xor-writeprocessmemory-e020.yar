rule TTP_XOR_WriteProcessMemory_e020 {
  strings:
    $key_e020 = { b7 52 [2] 85 70 [2] 83 45 [2] ad 45 [2] 92 59 }

  condition:
    any of them
}