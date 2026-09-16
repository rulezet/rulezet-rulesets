rule TTP_XOR_WriteProcessMemory_dded {
  strings:
    $key_dded = { 8a 9f [2] b8 bd [2] be 88 [2] 90 88 [2] af 94 }

  condition:
    any of them
}