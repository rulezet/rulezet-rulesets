rule TTP_XOR_WriteProcessMemory_0294 {
  strings:
    $key_0294 = { 55 e6 [2] 67 c4 [2] 61 f1 [2] 4f f1 [2] 70 ed }

  condition:
    any of them
}