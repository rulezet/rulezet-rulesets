rule TTP_XOR_WriteProcessMemory_ac8c {
  strings:
    $key_ac8c = { fb fe [2] c9 dc [2] cf e9 [2] e1 e9 [2] de f5 }

  condition:
    any of them
}