rule TTP_XOR_WriteProcessMemory_ddf8 {
  strings:
    $key_ddf8 = { 8a 8a [2] b8 a8 [2] be 9d [2] 90 9d [2] af 81 }

  condition:
    any of them
}