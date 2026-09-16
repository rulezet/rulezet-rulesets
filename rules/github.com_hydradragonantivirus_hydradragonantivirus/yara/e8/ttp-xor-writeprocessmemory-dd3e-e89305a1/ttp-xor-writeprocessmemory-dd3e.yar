rule TTP_XOR_WriteProcessMemory_dd3e {
  strings:
    $key_dd3e = { 8a 4c [2] b8 6e [2] be 5b [2] 90 5b [2] af 47 }

  condition:
    any of them
}