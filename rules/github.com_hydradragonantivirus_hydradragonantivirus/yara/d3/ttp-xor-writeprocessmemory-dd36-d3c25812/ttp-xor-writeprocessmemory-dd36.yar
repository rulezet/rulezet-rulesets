rule TTP_XOR_WriteProcessMemory_dd36 {
  strings:
    $key_dd36 = { 8a 44 [2] b8 66 [2] be 53 [2] 90 53 [2] af 4f }

  condition:
    any of them
}