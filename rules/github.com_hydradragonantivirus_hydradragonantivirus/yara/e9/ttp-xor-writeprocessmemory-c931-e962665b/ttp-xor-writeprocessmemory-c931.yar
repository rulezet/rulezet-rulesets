rule TTP_XOR_WriteProcessMemory_c931 {
  strings:
    $key_c931 = { 9e 43 [2] ac 61 [2] aa 54 [2] 84 54 [2] bb 48 }

  condition:
    any of them
}