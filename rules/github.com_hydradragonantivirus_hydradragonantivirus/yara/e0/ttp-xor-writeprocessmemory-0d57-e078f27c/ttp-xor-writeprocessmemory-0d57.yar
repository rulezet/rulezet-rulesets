rule TTP_XOR_WriteProcessMemory_0d57 {
  strings:
    $key_0d57 = { 5a 25 [2] 68 07 [2] 6e 32 [2] 40 32 [2] 7f 2e }

  condition:
    any of them
}