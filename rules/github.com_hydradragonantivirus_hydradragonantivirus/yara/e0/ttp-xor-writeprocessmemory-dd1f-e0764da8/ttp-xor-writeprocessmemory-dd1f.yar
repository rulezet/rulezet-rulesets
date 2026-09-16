rule TTP_XOR_WriteProcessMemory_dd1f {
  strings:
    $key_dd1f = { 8a 6d [2] b8 4f [2] be 7a [2] 90 7a [2] af 66 }

  condition:
    any of them
}