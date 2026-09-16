rule TTP_XOR_WriteProcessMemory_e194 {
  strings:
    $key_e194 = { b6 e6 [2] 84 c4 [2] 82 f1 [2] ac f1 [2] 93 ed }

  condition:
    any of them
}