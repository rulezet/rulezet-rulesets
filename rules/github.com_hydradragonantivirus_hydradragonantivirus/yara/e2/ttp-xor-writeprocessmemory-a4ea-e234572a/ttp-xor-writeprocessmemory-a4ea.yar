rule TTP_XOR_WriteProcessMemory_a4ea {
  strings:
    $key_a4ea = { f3 98 [2] c1 ba [2] c7 8f [2] e9 8f [2] d6 93 }

  condition:
    any of them
}