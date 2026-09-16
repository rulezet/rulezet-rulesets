rule TTP_XOR_WriteProcessMemory_2dad {
  strings:
    $key_2dad = { 7a df [2] 48 fd [2] 4e c8 [2] 60 c8 [2] 5f d4 }

  condition:
    any of them
}