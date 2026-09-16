rule TTP_XOR_WriteProcessMemory_163d {
  strings:
    $key_163d = { 41 4f [2] 73 6d [2] 75 58 [2] 5b 58 [2] 64 44 }

  condition:
    any of them
}