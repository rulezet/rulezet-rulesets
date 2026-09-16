rule TTP_XOR_WriteProcessMemory_430d {
  strings:
    $key_430d = { 14 7f [2] 26 5d [2] 20 68 [2] 0e 68 [2] 31 74 }

  condition:
    any of them
}