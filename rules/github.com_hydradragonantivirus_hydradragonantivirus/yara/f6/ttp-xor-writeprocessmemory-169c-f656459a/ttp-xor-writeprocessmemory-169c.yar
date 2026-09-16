rule TTP_XOR_WriteProcessMemory_169c {
  strings:
    $key_169c = { 41 ee [2] 73 cc [2] 75 f9 [2] 5b f9 [2] 64 e5 }

  condition:
    any of them
}