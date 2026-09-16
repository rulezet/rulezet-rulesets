rule TTP_XOR_WriteProcessMemory_5b0d {
  strings:
    $key_5b0d = { 0c 7f [2] 3e 5d [2] 38 68 [2] 16 68 [2] 29 74 }

  condition:
    any of them
}