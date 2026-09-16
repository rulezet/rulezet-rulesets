rule TTP_XOR_WriteProcessMemory_a4fc {
  strings:
    $key_a4fc = { f3 8e [2] c1 ac [2] c7 99 [2] e9 99 [2] d6 85 }

  condition:
    any of them
}