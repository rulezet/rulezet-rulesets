rule TTP_XOR_WriteProcessMemory_6bad {
  strings:
    $key_6bad = { 3c df [2] 0e fd [2] 08 c8 [2] 26 c8 [2] 19 d4 }

  condition:
    any of them
}