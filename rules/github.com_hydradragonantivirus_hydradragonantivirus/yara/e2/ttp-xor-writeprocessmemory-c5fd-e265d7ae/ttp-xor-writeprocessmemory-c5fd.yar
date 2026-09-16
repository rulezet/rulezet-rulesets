rule TTP_XOR_WriteProcessMemory_c5fd {
  strings:
    $key_c5fd = { 92 8f [2] a0 ad [2] a6 98 [2] 88 98 [2] b7 84 }

  condition:
    any of them
}