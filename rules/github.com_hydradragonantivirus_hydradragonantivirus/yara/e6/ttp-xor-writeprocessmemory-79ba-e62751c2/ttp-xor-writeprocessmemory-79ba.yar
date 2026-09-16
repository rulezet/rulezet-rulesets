rule TTP_XOR_WriteProcessMemory_79ba {
  strings:
    $key_79ba = { 2e c8 [2] 1c ea [2] 1a df [2] 34 df [2] 0b c3 }

  condition:
    any of them
}