rule TTP_XOR_WriteProcessMemory_c51a {
  strings:
    $key_c51a = { 92 68 [2] a0 4a [2] a6 7f [2] 88 7f [2] b7 63 }

  condition:
    any of them
}