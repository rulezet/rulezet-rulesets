rule TTP_XOR_WriteProcessMemory_0062 {
  strings:
    $key_0062 = { 57 10 [2] 65 32 [2] 63 07 [2] 4d 07 [2] 72 1b }

  condition:
    any of them
}