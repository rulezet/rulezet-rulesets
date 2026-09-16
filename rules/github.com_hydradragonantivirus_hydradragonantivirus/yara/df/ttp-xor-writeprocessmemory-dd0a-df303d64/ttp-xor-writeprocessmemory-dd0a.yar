rule TTP_XOR_WriteProcessMemory_dd0a {
  strings:
    $key_dd0a = { 8a 78 [2] b8 5a [2] be 6f [2] 90 6f [2] af 73 }

  condition:
    any of them
}