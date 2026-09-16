rule TTP_XOR_WriteProcessMemory_c54e {
  strings:
    $key_c54e = { 92 3c [2] a0 1e [2] a6 2b [2] 88 2b [2] b7 37 }

  condition:
    any of them
}