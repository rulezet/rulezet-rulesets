rule TTP_XOR_WriteProcessMemory_7747 {
  strings:
    $key_7747 = { 20 35 [2] 12 17 [2] 14 22 [2] 3a 22 [2] 05 3e }

  condition:
    any of them
}