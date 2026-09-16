rule TTP_XOR_WriteProcessMemory_8894 {
  strings:
    $key_8894 = { df e6 [2] ed c4 [2] eb f1 [2] c5 f1 [2] fa ed }

  condition:
    any of them
}