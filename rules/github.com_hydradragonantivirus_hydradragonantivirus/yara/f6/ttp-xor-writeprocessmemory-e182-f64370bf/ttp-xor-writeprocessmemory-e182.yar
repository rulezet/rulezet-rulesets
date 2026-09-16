rule TTP_XOR_WriteProcessMemory_e182 {
  strings:
    $key_e182 = { b6 f0 [2] 84 d2 [2] 82 e7 [2] ac e7 [2] 93 fb }

  condition:
    any of them
}