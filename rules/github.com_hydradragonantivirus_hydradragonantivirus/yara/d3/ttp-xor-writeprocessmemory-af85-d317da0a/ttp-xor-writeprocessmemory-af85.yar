rule TTP_XOR_WriteProcessMemory_af85 {
  strings:
    $key_af85 = { f8 f7 [2] ca d5 [2] cc e0 [2] e2 e0 [2] dd fc }

  condition:
    any of them
}