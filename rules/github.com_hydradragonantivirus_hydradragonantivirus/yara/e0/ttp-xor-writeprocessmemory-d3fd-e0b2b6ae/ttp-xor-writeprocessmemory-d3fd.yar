rule TTP_XOR_WriteProcessMemory_d3fd {
  strings:
    $key_d3fd = { 84 8f [2] b6 ad [2] b0 98 [2] 9e 98 [2] a1 84 }

  condition:
    any of them
}