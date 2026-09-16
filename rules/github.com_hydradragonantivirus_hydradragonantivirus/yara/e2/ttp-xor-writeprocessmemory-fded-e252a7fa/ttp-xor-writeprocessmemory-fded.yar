rule TTP_XOR_WriteProcessMemory_fded {
  strings:
    $key_fded = { aa 9f [2] 98 bd [2] 9e 88 [2] b0 88 [2] 8f 94 }

  condition:
    any of them
}