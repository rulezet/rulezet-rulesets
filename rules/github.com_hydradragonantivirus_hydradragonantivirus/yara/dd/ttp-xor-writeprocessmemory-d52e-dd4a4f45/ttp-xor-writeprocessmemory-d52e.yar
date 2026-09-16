rule TTP_XOR_WriteProcessMemory_d52e {
  strings:
    $key_d52e = { 82 5c [2] b0 7e [2] b6 4b [2] 98 4b [2] a7 57 }

  condition:
    any of them
}