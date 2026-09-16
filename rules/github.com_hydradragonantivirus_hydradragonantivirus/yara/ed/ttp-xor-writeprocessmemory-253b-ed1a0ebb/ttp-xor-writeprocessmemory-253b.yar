rule TTP_XOR_WriteProcessMemory_253b {
  strings:
    $key_253b = { 72 49 [2] 40 6b [2] 46 5e [2] 68 5e [2] 57 42 }

  condition:
    any of them
}