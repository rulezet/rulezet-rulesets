rule TTP_XOR_WriteProcessMemory_5dba {
  strings:
    $key_5dba = { 0a c8 [2] 38 ea [2] 3e df [2] 10 df [2] 2f c3 }

  condition:
    any of them
}