rule TTP_XOR_WriteProcessMemory_679c {
  strings:
    $key_679c = { 30 ee [2] 02 cc [2] 04 f9 [2] 2a f9 [2] 15 e5 }

  condition:
    any of them
}