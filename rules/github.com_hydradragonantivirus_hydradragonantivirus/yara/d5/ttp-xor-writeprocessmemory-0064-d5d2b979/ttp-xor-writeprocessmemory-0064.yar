rule TTP_XOR_WriteProcessMemory_0064 {
  strings:
    $key_0064 = { 57 16 [2] 65 34 [2] 63 01 [2] 4d 01 [2] 72 1d }

  condition:
    any of them
}