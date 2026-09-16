rule TTP_XOR_WriteProcessMemory_dd2c {
  strings:
    $key_dd2c = { 8a 5e [2] b8 7c [2] be 49 [2] 90 49 [2] af 55 }

  condition:
    any of them
}