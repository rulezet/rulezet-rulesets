rule TTP_XOR_WriteProcessMemory_798e {
  strings:
    $key_798e = { 2e fc [2] 1c de [2] 1a eb [2] 34 eb [2] 0b f7 }

  condition:
    any of them
}