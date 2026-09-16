rule TTP_XOR_WriteProcessMemory_0194 {
  strings:
    $key_0194 = { 56 e6 [2] 64 c4 [2] 62 f1 [2] 4c f1 [2] 73 ed }

  condition:
    any of them
}