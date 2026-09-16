rule TTP_XOR_WriteProcessMemory_dd08 {
  strings:
    $key_dd08 = { 8a 7a [2] b8 58 [2] be 6d [2] 90 6d [2] af 71 }

  condition:
    any of them
}