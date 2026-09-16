rule TTP_XOR_WriteProcessMemory_8bea {
  strings:
    $key_8bea = { dc 98 [2] ee ba [2] e8 8f [2] c6 8f [2] f9 93 }

  condition:
    any of them
}