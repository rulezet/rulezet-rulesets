rule TTP_XOR_WriteProcessMemory_750d {
  strings:
    $key_750d = { 22 7f [2] 10 5d [2] 16 68 [2] 38 68 [2] 07 74 }

  condition:
    any of them
}