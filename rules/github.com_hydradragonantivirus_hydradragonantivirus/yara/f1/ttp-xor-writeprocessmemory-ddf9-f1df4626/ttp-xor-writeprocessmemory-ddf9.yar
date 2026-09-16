rule TTP_XOR_WriteProcessMemory_ddf9 {
  strings:
    $key_ddf9 = { 8a 8b [2] b8 a9 [2] be 9c [2] 90 9c [2] af 80 }

  condition:
    any of them
}