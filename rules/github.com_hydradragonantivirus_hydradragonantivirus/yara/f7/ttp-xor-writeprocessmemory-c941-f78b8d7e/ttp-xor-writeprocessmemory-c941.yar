rule TTP_XOR_WriteProcessMemory_c941 {
  strings:
    $key_c941 = { 9e 33 [2] ac 11 [2] aa 24 [2] 84 24 [2] bb 38 }

  condition:
    any of them
}