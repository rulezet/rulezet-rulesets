rule TTP_XOR_WriteProcessMemory_ec9c {
  strings:
    $key_ec9c = { bb ee [2] 89 cc [2] 8f f9 [2] a1 f9 [2] 9e e5 }

  condition:
    any of them
}