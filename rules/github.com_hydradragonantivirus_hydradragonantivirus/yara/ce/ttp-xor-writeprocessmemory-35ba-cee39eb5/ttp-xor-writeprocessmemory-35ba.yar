rule TTP_XOR_WriteProcessMemory_35ba {
  strings:
    $key_35ba = { 62 c8 [2] 50 ea [2] 56 df [2] 78 df [2] 47 c3 }

  condition:
    any of them
}