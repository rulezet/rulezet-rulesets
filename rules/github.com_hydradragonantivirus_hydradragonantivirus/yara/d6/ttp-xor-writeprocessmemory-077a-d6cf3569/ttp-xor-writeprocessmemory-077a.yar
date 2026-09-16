rule TTP_XOR_WriteProcessMemory_077a {
  strings:
    $key_077a = { 50 08 [2] 62 2a [2] 64 1f [2] 4a 1f [2] 75 03 }

  condition:
    any of them
}