rule TTP_XOR_WriteProcessMemory_822d {
  strings:
    $key_822d = { d5 5f [2] e7 7d [2] e1 48 [2] cf 48 [2] f0 54 }

  condition:
    any of them
}