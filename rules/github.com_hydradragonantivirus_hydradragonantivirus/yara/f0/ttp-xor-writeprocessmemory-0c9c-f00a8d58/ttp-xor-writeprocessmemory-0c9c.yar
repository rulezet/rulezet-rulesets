rule TTP_XOR_WriteProcessMemory_0c9c {
  strings:
    $key_0c9c = { 5b ee [2] 69 cc [2] 6f f9 [2] 41 f9 [2] 7e e5 }

  condition:
    any of them
}