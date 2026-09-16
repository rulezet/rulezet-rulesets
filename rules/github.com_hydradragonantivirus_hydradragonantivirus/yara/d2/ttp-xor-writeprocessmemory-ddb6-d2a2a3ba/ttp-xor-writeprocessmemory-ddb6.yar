rule TTP_XOR_WriteProcessMemory_ddb6 {
  strings:
    $key_ddb6 = { 8a c4 [2] b8 e6 [2] be d3 [2] 90 d3 [2] af cf }

  condition:
    any of them
}