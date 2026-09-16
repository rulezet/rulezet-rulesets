rule TTP_XOR_WriteProcessMemory_cca0 {
  strings:
    $key_cca0 = { 9b d2 [2] a9 f0 [2] af c5 [2] 81 c5 [2] be d9 }

  condition:
    any of them
}