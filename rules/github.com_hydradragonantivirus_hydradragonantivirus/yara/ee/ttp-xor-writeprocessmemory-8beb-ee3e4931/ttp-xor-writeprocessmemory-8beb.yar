rule TTP_XOR_WriteProcessMemory_8beb {
  strings:
    $key_8beb = { dc 99 [2] ee bb [2] e8 8e [2] c6 8e [2] f9 92 }

  condition:
    any of them
}