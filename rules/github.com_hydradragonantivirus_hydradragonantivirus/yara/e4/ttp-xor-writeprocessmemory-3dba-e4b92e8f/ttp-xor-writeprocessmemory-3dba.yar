rule TTP_XOR_WriteProcessMemory_3dba {
  strings:
    $key_3dba = { 6a c8 [2] 58 ea [2] 5e df [2] 70 df [2] 4f c3 }

  condition:
    any of them
}