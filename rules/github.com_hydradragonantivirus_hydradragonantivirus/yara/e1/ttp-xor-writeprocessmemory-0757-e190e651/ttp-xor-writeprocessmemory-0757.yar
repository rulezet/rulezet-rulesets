rule TTP_XOR_WriteProcessMemory_0757 {
  strings:
    $key_0757 = { 50 25 [2] 62 07 [2] 64 32 [2] 4a 32 [2] 75 2e }

  condition:
    any of them
}