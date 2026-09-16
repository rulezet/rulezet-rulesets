rule TTP_XOR_WriteProcessMemory_559c {
  strings:
    $key_559c = { 02 ee [2] 30 cc [2] 36 f9 [2] 18 f9 [2] 27 e5 }

  condition:
    any of them
}