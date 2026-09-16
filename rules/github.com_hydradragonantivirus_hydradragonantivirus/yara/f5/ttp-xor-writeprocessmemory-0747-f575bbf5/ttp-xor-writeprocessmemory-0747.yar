rule TTP_XOR_WriteProcessMemory_0747 {
  strings:
    $key_0747 = { 50 35 [2] 62 17 [2] 64 22 [2] 4a 22 [2] 75 3e }

  condition:
    any of them
}