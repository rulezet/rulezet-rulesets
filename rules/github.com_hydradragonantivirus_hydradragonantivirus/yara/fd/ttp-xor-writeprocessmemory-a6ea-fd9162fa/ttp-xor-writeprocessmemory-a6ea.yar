rule TTP_XOR_WriteProcessMemory_a6ea {
  strings:
    $key_a6ea = { f1 98 [2] c3 ba [2] c5 8f [2] eb 8f [2] d4 93 }

  condition:
    any of them
}