rule TTP_XOR_WriteProcessMemory_253d {
  strings:
    $key_253d = { 72 4f [2] 40 6d [2] 46 58 [2] 68 58 [2] 57 44 }

  condition:
    any of them
}