rule TTP_XOR_WriteProcessMemory_59ba {
  strings:
    $key_59ba = { 0e c8 [2] 3c ea [2] 3a df [2] 14 df [2] 2b c3 }

  condition:
    any of them
}