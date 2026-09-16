rule TTP_XOR_WriteProcessMemory_ddd8 {
  strings:
    $key_ddd8 = { 8a aa [2] b8 88 [2] be bd [2] 90 bd [2] af a1 }

  condition:
    any of them
}