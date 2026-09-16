rule TTP_XOR_WriteProcessMemory_758b {
  strings:
    $key_758b = { 22 f9 [2] 10 db [2] 16 ee [2] 38 ee [2] 07 f2 }

  condition:
    any of them
}