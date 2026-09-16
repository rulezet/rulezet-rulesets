rule TTP_XOR_WriteProcessMemory_de89 {
  strings:
    $key_de89 = { 89 fb [2] bb d9 [2] bd ec [2] 93 ec [2] ac f0 }

  condition:
    any of them
}