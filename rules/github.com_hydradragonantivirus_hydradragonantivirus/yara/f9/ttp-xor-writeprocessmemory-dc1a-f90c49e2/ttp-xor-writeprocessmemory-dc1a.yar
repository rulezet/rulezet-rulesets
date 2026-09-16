rule TTP_XOR_WriteProcessMemory_dc1a {
  strings:
    $key_dc1a = { 8b 68 [2] b9 4a [2] bf 7f [2] 91 7f [2] ae 63 }

  condition:
    any of them
}