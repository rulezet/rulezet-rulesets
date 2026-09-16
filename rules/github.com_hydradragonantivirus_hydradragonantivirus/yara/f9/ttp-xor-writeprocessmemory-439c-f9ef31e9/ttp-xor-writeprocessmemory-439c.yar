rule TTP_XOR_WriteProcessMemory_439c {
  strings:
    $key_439c = { 14 ee [2] 26 cc [2] 20 f9 [2] 0e f9 [2] 31 e5 }

  condition:
    any of them
}