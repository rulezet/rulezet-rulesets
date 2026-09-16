rule TTP_XOR_WriteProcessMemory_182d {
  strings:
    $key_182d = { 4f 5f [2] 7d 7d [2] 7b 48 [2] 55 48 [2] 6a 54 }

  condition:
    any of them
}