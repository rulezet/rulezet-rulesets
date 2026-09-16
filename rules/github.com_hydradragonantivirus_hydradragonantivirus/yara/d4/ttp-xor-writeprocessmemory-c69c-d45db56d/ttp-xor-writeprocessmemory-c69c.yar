rule TTP_XOR_WriteProcessMemory_c69c {
  strings:
    $key_c69c = { 91 ee [2] a3 cc [2] a5 f9 [2] 8b f9 [2] b4 e5 }

  condition:
    any of them
}