rule TTP_XOR_WriteProcessMemory_8eeb {
  strings:
    $key_8eeb = { d9 99 [2] eb bb [2] ed 8e [2] c3 8e [2] fc 92 }

  condition:
    any of them
}