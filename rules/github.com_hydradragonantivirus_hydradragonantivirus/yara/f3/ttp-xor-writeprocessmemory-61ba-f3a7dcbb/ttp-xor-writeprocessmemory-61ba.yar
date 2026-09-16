rule TTP_XOR_WriteProcessMemory_61ba {
  strings:
    $key_61ba = { 36 c8 [2] 04 ea [2] 02 df [2] 2c df [2] 13 c3 }

  condition:
    any of them
}