rule TTP_XOR_WriteProcessMemory_c63a {
  strings:
    $key_c63a = { 91 48 [2] a3 6a [2] a5 5f [2] 8b 5f [2] b4 43 }

  condition:
    any of them
}