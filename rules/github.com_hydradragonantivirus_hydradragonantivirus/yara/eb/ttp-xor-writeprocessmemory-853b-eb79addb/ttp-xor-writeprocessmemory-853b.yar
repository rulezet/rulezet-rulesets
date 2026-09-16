rule TTP_XOR_WriteProcessMemory_853b {
  strings:
    $key_853b = { d2 49 [2] e0 6b [2] e6 5e [2] c8 5e [2] f7 42 }

  condition:
    any of them
}