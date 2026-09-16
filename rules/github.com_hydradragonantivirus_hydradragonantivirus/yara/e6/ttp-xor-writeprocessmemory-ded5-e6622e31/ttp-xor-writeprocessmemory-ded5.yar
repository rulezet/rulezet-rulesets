rule TTP_XOR_WriteProcessMemory_ded5 {
  strings:
    $key_ded5 = { 89 a7 [2] bb 85 [2] bd b0 [2] 93 b0 [2] ac ac }

  condition:
    any of them
}