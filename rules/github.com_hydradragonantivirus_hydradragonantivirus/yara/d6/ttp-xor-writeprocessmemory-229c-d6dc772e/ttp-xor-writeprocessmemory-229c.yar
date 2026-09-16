rule TTP_XOR_WriteProcessMemory_229c {
  strings:
    $key_229c = { 75 ee [2] 47 cc [2] 41 f9 [2] 6f f9 [2] 50 e5 }

  condition:
    any of them
}