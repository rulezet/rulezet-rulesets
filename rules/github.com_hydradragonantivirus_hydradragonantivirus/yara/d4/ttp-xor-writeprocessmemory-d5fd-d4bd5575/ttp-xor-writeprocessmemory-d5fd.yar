rule TTP_XOR_WriteProcessMemory_d5fd {
  strings:
    $key_d5fd = { 82 8f [2] b0 ad [2] b6 98 [2] 98 98 [2] a7 84 }

  condition:
    any of them
}