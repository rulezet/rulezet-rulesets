rule TTP_XOR_WriteProcessMemory_5dad {
  strings:
    $key_5dad = { 0a df [2] 38 fd [2] 3e c8 [2] 10 c8 [2] 2f d4 }

  condition:
    any of them
}