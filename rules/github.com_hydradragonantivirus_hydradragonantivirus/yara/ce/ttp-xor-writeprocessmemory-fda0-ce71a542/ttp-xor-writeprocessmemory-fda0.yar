rule TTP_XOR_WriteProcessMemory_fda0 {
  strings:
    $key_fda0 = { aa d2 [2] 98 f0 [2] 9e c5 [2] b0 c5 [2] 8f d9 }

  condition:
    any of them
}