rule TTP_XOR_WriteProcessMemory_578e {
  strings:
    $key_578e = { 00 fc [2] 32 de [2] 34 eb [2] 1a eb [2] 25 f7 }

  condition:
    any of them
}