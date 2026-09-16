rule TTP_XOR_WriteProcessMemory_dd21 {
  strings:
    $key_dd21 = { 8a 53 [2] b8 71 [2] be 44 [2] 90 44 [2] af 58 }

  condition:
    any of them
}