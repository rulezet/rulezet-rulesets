rule TTP_XOR_WriteProcessMemory_4d99 {
  strings:
    $key_4d99 = { 1a eb [2] 28 c9 [2] 2e fc [2] 00 fc [2] 3f e0 }

  condition:
    any of them
}