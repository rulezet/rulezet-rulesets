rule TTP_XOR_WriteProcessMemory_d2fd {
  strings:
    $key_d2fd = { 85 8f [2] b7 ad [2] b1 98 [2] 9f 98 [2] a0 84 }

  condition:
    any of them
}