rule TTP_XOR_WriteProcessMemory_2457 {
  strings:
    $key_2457 = { 73 25 [2] 41 07 [2] 47 32 [2] 69 32 [2] 56 2e }

  condition:
    any of them
}