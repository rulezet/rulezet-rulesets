rule TTP_XOR_WriteProcessMemory_dd0b {
  strings:
    $key_dd0b = { 8a 79 [2] b8 5b [2] be 6e [2] 90 6e [2] af 72 }

  condition:
    any of them
}