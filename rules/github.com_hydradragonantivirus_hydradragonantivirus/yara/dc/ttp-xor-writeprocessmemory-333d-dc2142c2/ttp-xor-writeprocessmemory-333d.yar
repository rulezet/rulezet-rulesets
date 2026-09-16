rule TTP_XOR_WriteProcessMemory_333d {
  strings:
    $key_333d = { 64 4f [2] 56 6d [2] 50 58 [2] 7e 58 [2] 41 44 }

  condition:
    any of them
}