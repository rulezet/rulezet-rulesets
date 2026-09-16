rule TTP_XOR_WriteProcessMemory_dd83 {
  strings:
    $key_dd83 = { 8a f1 [2] b8 d3 [2] be e6 [2] 90 e6 [2] af fa }

  condition:
    any of them
}