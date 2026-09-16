rule TTP_XOR_WriteProcessMemory_e294 {
  strings:
    $key_e294 = { b5 e6 [2] 87 c4 [2] 81 f1 [2] af f1 [2] 90 ed }

  condition:
    any of them
}