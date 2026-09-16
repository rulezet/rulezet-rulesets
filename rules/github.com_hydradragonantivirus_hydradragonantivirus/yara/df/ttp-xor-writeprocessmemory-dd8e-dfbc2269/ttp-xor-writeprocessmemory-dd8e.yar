rule TTP_XOR_WriteProcessMemory_dd8e {
  strings:
    $key_dd8e = { 8a fc [2] b8 de [2] be eb [2] 90 eb [2] af f7 }

  condition:
    any of them
}