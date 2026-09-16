rule TTP_XOR_WriteProcessMemory_dd0c {
  strings:
    $key_dd0c = { 8a 7e [2] b8 5c [2] be 69 [2] 90 69 [2] af 75 }

  condition:
    any of them
}