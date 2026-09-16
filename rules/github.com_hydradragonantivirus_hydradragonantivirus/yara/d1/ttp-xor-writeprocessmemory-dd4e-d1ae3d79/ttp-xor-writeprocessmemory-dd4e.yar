rule TTP_XOR_WriteProcessMemory_dd4e {
  strings:
    $key_dd4e = { 8a 3c [2] b8 1e [2] be 2b [2] 90 2b [2] af 37 }

  condition:
    any of them
}