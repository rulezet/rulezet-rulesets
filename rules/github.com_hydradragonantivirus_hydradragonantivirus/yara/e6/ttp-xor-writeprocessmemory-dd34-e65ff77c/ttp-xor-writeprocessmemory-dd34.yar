rule TTP_XOR_WriteProcessMemory_dd34 {
  strings:
    $key_dd34 = { 8a 46 [2] b8 64 [2] be 51 [2] 90 51 [2] af 4d }

  condition:
    any of them
}