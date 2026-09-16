rule TTP_XOR_WriteProcessMemory_5d5d {
  strings:
    $key_5d5d = { 0a 2f [2] 38 0d [2] 3e 38 [2] 10 38 [2] 2f 24 }

  condition:
    any of them
}