rule TTP_XOR_WriteProcessMemory_c71a {
  strings:
    $key_c71a = { 90 68 [2] a2 4a [2] a4 7f [2] 8a 7f [2] b5 63 }

  condition:
    any of them
}