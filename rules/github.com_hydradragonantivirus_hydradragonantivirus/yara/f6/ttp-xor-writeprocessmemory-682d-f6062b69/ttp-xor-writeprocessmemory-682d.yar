rule TTP_XOR_WriteProcessMemory_682d {
  strings:
    $key_682d = { 3f 5f [2] 0d 7d [2] 0b 48 [2] 25 48 [2] 1a 54 }

  condition:
    any of them
}