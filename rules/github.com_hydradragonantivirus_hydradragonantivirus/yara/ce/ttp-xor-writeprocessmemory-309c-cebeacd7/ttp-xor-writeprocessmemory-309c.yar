rule TTP_XOR_WriteProcessMemory_309c {
  strings:
    $key_309c = { 67 ee [2] 55 cc [2] 53 f9 [2] 7d f9 [2] 42 e5 }

  condition:
    any of them
}