rule TTP_XOR_WriteProcessMemory_c7fd {
  strings:
    $key_c7fd = { 90 8f [2] a2 ad [2] a4 98 [2] 8a 98 [2] b5 84 }

  condition:
    any of them
}