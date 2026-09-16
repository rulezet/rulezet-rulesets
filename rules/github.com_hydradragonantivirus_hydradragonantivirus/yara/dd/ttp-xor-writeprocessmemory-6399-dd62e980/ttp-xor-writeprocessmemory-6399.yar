rule TTP_XOR_WriteProcessMemory_6399 {
  strings:
    $key_6399 = { 34 eb [2] 06 c9 [2] 00 fc [2] 2e fc [2] 11 e0 }

  condition:
    any of them
}