rule TTP_XOR_WriteProcessMemory_dd1d {
  strings:
    $key_dd1d = { 8a 6f [2] b8 4d [2] be 78 [2] 90 78 [2] af 64 }

  condition:
    any of them
}