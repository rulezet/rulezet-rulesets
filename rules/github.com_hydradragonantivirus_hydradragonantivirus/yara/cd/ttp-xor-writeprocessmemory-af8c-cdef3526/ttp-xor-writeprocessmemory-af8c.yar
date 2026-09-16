rule TTP_XOR_WriteProcessMemory_af8c {
  strings:
    $key_af8c = { f8 fe [2] ca dc [2] cc e9 [2] e2 e9 [2] dd f5 }

  condition:
    any of them
}