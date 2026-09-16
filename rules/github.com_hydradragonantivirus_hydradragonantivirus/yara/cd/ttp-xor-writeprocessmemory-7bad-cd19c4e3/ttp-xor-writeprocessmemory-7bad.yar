rule TTP_XOR_WriteProcessMemory_7bad {
  strings:
    $key_7bad = { 2c df [2] 1e fd [2] 18 c8 [2] 36 c8 [2] 09 d4 }

  condition:
    any of them
}