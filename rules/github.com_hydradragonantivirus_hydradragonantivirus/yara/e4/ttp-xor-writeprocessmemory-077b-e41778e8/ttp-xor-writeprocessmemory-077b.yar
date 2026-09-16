rule TTP_XOR_WriteProcessMemory_077b {
  strings:
    $key_077b = { 50 09 [2] 62 2b [2] 64 1e [2] 4a 1e [2] 75 02 }

  condition:
    any of them
}