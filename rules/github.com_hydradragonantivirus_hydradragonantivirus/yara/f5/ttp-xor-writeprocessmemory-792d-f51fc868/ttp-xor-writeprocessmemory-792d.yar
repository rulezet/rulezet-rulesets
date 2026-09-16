rule TTP_XOR_WriteProcessMemory_792d {
  strings:
    $key_792d = { 2e 5f [2] 1c 7d [2] 1a 48 [2] 34 48 [2] 0b 54 }

  condition:
    any of them
}