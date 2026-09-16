rule TTP_XOR_WriteProcessMemory_b4fc {
  strings:
    $key_b4fc = { e3 8e [2] d1 ac [2] d7 99 [2] f9 99 [2] c6 85 }

  condition:
    any of them
}