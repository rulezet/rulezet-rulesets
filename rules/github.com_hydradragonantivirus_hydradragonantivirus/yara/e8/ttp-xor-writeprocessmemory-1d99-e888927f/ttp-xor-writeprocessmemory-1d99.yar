rule TTP_XOR_WriteProcessMemory_1d99 {
  strings:
    $key_1d99 = { 4a eb [2] 78 c9 [2] 7e fc [2] 50 fc [2] 6f e0 }

  condition:
    any of them
}