rule TTP_XOR_WriteProcessMemory_3162 {
  strings:
    $key_3162 = { 66 10 [2] 54 32 [2] 52 07 [2] 7c 07 [2] 43 1b }

  condition:
    any of them
}