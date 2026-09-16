rule TTP_XOR_WriteProcessMemory_077c {
  strings:
    $key_077c = { 50 0e [2] 62 2c [2] 64 19 [2] 4a 19 [2] 75 05 }

  condition:
    any of them
}