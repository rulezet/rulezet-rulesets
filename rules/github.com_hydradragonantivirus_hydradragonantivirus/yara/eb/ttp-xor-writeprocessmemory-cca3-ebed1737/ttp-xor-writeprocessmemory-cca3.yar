rule TTP_XOR_WriteProcessMemory_cca3 {
  strings:
    $key_cca3 = { 9b d1 [2] a9 f3 [2] af c6 [2] 81 c6 [2] be da }

  condition:
    any of them
}