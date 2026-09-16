rule TTP_XOR_WriteProcessMemory_0dba {
  strings:
    $key_0dba = { 5a c8 [2] 68 ea [2] 6e df [2] 40 df [2] 7f c3 }

  condition:
    any of them
}