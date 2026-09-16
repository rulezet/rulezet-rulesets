rule TTP_XOR_WriteProcessMemory_44fd {
  strings:
    $key_44fd = { 13 8f [2] 21 ad [2] 27 98 [2] 09 98 [2] 36 84 }

  condition:
    any of them
}