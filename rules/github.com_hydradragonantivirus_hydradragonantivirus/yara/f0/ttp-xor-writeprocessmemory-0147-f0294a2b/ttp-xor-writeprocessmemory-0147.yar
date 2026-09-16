rule TTP_XOR_WriteProcessMemory_0147 {
  strings:
    $key_0147 = { 56 35 [2] 64 17 [2] 62 22 [2] 4c 22 [2] 73 3e }

  condition:
    any of them
}