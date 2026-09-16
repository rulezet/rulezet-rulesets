rule TTP_XOR_WriteProcessMemory_532d {
  strings:
    $key_532d = { 04 5f [2] 36 7d [2] 30 48 [2] 1e 48 [2] 21 54 }

  condition:
    any of them
}