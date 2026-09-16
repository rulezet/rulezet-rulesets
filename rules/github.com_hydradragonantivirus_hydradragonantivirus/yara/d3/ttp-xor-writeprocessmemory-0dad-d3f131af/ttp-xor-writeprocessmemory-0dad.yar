rule TTP_XOR_WriteProcessMemory_0dad {
  strings:
    $key_0dad = { 5a df [2] 68 fd [2] 6e c8 [2] 40 c8 [2] 7f d4 }

  condition:
    any of them
}