rule TTP_XOR_WriteProcessMemory_4cba {
  strings:
    $key_4cba = { 1b c8 [2] 29 ea [2] 2f df [2] 01 df [2] 3e c3 }

  condition:
    any of them
}