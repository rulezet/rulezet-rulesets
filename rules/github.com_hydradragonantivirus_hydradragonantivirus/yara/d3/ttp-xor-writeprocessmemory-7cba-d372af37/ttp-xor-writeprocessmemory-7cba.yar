rule TTP_XOR_WriteProcessMemory_7cba {
  strings:
    $key_7cba = { 2b c8 [2] 19 ea [2] 1f df [2] 31 df [2] 0e c3 }

  condition:
    any of them
}