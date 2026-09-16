rule TTP_XOR_WriteProcessMemory_dd61 {
  strings:
    $key_dd61 = { 8a 13 [2] b8 31 [2] be 04 [2] 90 04 [2] af 18 }

  condition:
    any of them
}