rule TTP_XOR_WriteProcessMemory_183d {
  strings:
    $key_183d = { 4f 4f [2] 7d 6d [2] 7b 58 [2] 55 58 [2] 6a 44 }

  condition:
    any of them
}