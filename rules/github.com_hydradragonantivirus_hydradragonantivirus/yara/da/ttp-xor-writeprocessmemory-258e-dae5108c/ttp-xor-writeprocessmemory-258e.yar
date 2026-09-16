rule TTP_XOR_WriteProcessMemory_258e {
  strings:
    $key_258e = { 72 fc [2] 40 de [2] 46 eb [2] 68 eb [2] 57 f7 }

  condition:
    any of them
}