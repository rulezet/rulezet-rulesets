rule TTP_XOR_WriteProcessMemory_0494 {
  strings:
    $key_0494 = { 53 e6 [2] 61 c4 [2] 67 f1 [2] 49 f1 [2] 76 ed }

  condition:
    any of them
}