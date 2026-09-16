rule TTP_XOR_WriteProcessMemory_7beb {
  strings:
    $key_7beb = { 2c 99 [2] 1e bb [2] 18 8e [2] 36 8e [2] 09 92 }

  condition:
    any of them
}