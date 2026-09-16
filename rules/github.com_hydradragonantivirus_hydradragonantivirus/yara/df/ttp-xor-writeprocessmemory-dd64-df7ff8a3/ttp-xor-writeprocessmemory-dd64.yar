rule TTP_XOR_WriteProcessMemory_dd64 {
  strings:
    $key_dd64 = { 8a 16 [2] b8 34 [2] be 01 [2] 90 01 [2] af 1d }

  condition:
    any of them
}